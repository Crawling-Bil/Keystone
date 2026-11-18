"""Real-browser checks of the content security policy and of output escaping.

* The policy forbids inline scripts, so every behaviour the pages need lives in a file under /static.  The tests open the pages
  and use the controls that used to depend on an inline script (the hardware catalogue, a planned converter form) to prove
  nothing was lost when the inline allowance was removed.
* A hostname or an object name taken from a capture is attacker-controlled text.  The three analyzer pages are fed names that look
  like markup and the result is searched for an element or a handler that came from them.

Skipped when Playwright or its Chromium is not installed.  Every capture is a short invented text built from the fixtures.
"""
from __future__ import annotations

import threading
from pathlib import Path

import pytest

playwright_api = pytest.importorskip("playwright.sync_api")

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
PAYLOAD = "<img/src=x/onerror=window.__xss=1>"


@pytest.fixture(scope="module")
def base_url():
    from werkzeug.serving import make_server

    from app import create_app

    server = make_server("127.0.0.1", 0, create_app(), threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(scope="module")
def browser():
    with playwright_api.sync_playwright() as p:
        try:
            chromium = p.chromium.launch()
        except Exception as error:                                   # noqa: BLE001 - the browser binary is not installed
            pytest.skip(f"Chromium is not available: {error}")
        yield chromium
        chromium.close()


@pytest.fixture()
def page(browser):
    context = browser.new_context(viewport={"width": 1500, "height": 1000})
    page = context.new_page()
    page.errors = []
    page.on("pageerror", lambda error: page.errors.append(str(error)))
    page.on("console", lambda message: message.type == "error" and page.errors.append(message.text))
    page.add_init_script("window.__xss = 0;")
    yield page
    context.close()


# ---------------------------------------------------------------- the policy itself

def test_the_policy_allows_no_inline_script_and_the_pages_carry_none(base_url, page):
    response = page.goto(f"{base_url}/")
    policy = response.headers["content-security-policy"]
    script_src = [part for part in policy.split(";") if part.strip().startswith("script-src")][0]
    assert "'unsafe-inline'" not in script_src and "'unsafe-eval'" not in script_src
    page.wait_for_load_state("networkidle")
    inline = page.eval_on_selector_all("script:not([src])", "nodes => nodes.map(node => node.textContent.slice(0, 60))")
    handlers = page.eval_on_selector_all("*", "nodes => nodes.filter(node => [...node.attributes].some(a => a.name.startsWith('on'))).length")
    assert inline == [] and handlers == 0
    assert page.errors == []


def test_the_saved_colour_theme_is_applied_before_the_page_is_used(base_url, page):
    page.add_init_script("try { localStorage.setItem('nes-theme', 'light'); } catch (e) {}")
    page.goto(f"{base_url}/")
    assert page.get_attribute("html", "data-theme") == "light"
    assert page.errors == []


# ---------------------------------------------------------------- controls that used to be an inline script

# The buttons are clicked with ``dispatch_event`` (the page's own click handler runs, no hit-testing): a real mouse click can land on
# another control while the freshly opened tree is still moving the layout, which made the test flaky on a busy machine.
def _catalog_states(page):
    return page.eval_on_selector_all("#hardware-catalog details.hw-node", "nodes => nodes.map(node => node.open)")


def test_the_hardware_catalog_expands_collapses_and_filters(base_url, page):
    page.goto(f"{base_url}/convert/router")
    page.wait_for_selector("#hardware-catalog")
    page.dispatch_event('#hardware-catalog [data-hw-action="expand"]', 'click')
    states = _catalog_states(page)
    assert states and all(states)
    page.dispatch_event('#hardware-catalog [data-hw-action="collapse"]', 'click')
    assert not any(_catalog_states(page))
    picker = page.query_selector("#hw-model-picker")
    assert picker is not None
    models = page.eval_on_selector_all("#hw-model-picker option", "options => options.map(option => option.value).filter(Boolean)")
    assert len(models) >= 2
    page.select_option("#hw-model-picker", models[0])
    visible = page.eval_on_selector_all("#hardware-catalog details.hw-model:not(.is-hidden)", "cards => cards.map(card => card.dataset.model)")
    assert visible == [models[0]]
    page.select_option("#hw-model-picker", "")
    assert page.eval_on_selector_all("#hardware-catalog details.hw-model:not(.is-hidden)", "cards => cards.length") >= 2
    assert page.errors == []


def test_the_catalog_still_works_after_a_move_between_pages_without_a_reload(base_url, page):
    page.goto(f"{base_url}/convert/switch")
    page.wait_for_selector("#hardware-catalog")
    page.click('#suite-sidebar a[href="/convert/router"]')
    page.wait_for_url("**/convert/router")
    page.wait_for_selector("#hardware-catalog #hw-model-picker")
    page.dispatch_event('#hardware-catalog [data-hw-action="expand"]', 'click')
    assert all(_catalog_states(page))
    page.dispatch_event('#hardware-catalog [data-hw-action="collapse"]', 'click')
    assert not any(_catalog_states(page))
    assert page.errors == []


def test_a_planned_converter_form_does_not_submit(base_url, page):
    page.goto(f"{base_url}/convert/router")
    page.wait_for_selector("form[data-planned]")
    prevented = page.evaluate("""() => {
        const form = document.querySelector('form[data-planned]');
        const event = new Event('submit', { bubbles: true, cancelable: true });
        form.dispatchEvent(event);
        return event.defaultPrevented;
    }""")
    assert prevented is True


# ---------------------------------------------------------------- names taken from a capture are text, never markup

def _poisoned(tmp_path, fixture, names):
    text = (FIXTURES / fixture).read_text(encoding="utf-8")
    for name in names:
        assert name in text, name
        text = text.replace(name, PAYLOAD)
    path = tmp_path / Path(fixture).name
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize("route, fixture, names", [
    ("/load-balancer-analyzer", "loadbalancer/bigip_capture_synthetic.txt", ["lb-hq-01.corp.example.com", "pool_web"]),
    ("/router-analyzer", "router/synthetic_bad_ios_router.txt", ["lab-r1", "EDGE-IN"]),
    ("/firewall-analyzer", "firewall/fortigate_synthetic_7.2.conf", ["FW-HQ-01", "HQ-DR-VPN"]),
])
def test_a_name_that_looks_like_markup_is_shown_as_text_on_every_tab(base_url, page, tmp_path, route, fixture, names):
    path = _poisoned(tmp_path, fixture, names)
    page.goto(f"{base_url}{route}")
    page.set_input_files('[data-role="file-input"]', str(path))
    page.click('[data-role="analyze"]')
    page.wait_for_selector('[data-role="result"]:not(.hidden) .an-tabs', timeout=30000)
    for tab in range(page.locator(".an-tabs button").count()):
        page.locator(".an-tabs button").nth(tab).click()
        page.wait_for_timeout(50)
    injected = page.eval_on_selector_all("img[src='x'], [onerror], [onload]", "nodes => nodes.length")
    assert injected == 0
    assert page.evaluate("window.__xss") == 0
    assert "&lt;img" in page.inner_html("body") or "<img/src=x" in page.inner_text("body")     # the name is on screen, as text
