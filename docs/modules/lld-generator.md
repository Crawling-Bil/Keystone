# LLD Generator

Writes the Word LLD from an LLD index: master template, chapter tree, tables and images, project placeholders and Document Acceptance. It is the former Document Generator (Crawling-Bil/Document-Generator v1.0.5) moved into Keystone.

Page: `/lld-generator` (sidebar group Document). Code: `features/lld_generator/` (routes, store, service) and `core/docgen/` (the Word engine, shared with the generators that come later, such as an Implementation Generator).

## Flow

1. LLD Index: build, then **Open in LLD Generator**. A new project on the master template, or the same project updated when the customer, project name and code match.
2. LLD Generator: upload topology and rack pictures, fix text, set the customer logo and version in Project settings.
3. **Generate & Download**: the .docx with placeholders filled, logo on the cover, fields updated when Word opens it.

Excel stays an option: **Import dari Excel Index** reads any LLD Content Index workbook (modes Tambahkan, Ganti, Perbarui).

## Parts

| Part | Does | Does not |
| --- | --- | --- |
| `core/docgen/docgen.py` | Builds the .docx from a template and a chapter tree (heading numbers, tables with merges, colours and alignment, captions, landscape for wide tables) | Know about projects, storage or HTTP |
| `core/docgen/importer.py` | Reads an LLD Content Index workbook into chapters and blocks, and its `Project` sheet | Write anything |
| `core/docgen/placeholders.py` | Fills `{{project_name}}`, `{{customer}}`, `{{project_code}}`, `{{version}}`, `{{date}}`, `{{year}}`, `{{company}}`, `{{prepared_by}}` in body, headers, footers and text boxes; swaps the `{{customer_logo}}` picture | Decide the values |
| `features/lld_generator/store.py` | Tables `lld_gen_templates`, `lld_gen_projects`, `lld_gen_chapters`, `lld_gen_blocks` in `data/nes.db`; `import_index` (append, replace, update) in one transaction | Files |
| `features/lld_generator/service.py` | Files in `data/lld_generator/` (templates, uploads per project, outputs), generate, LLD Index hand-off, legacy import, 7-day output cleanup | HTTP |
| `features/lld_generator/routes.py` | The JSON API, same paths and bodies as the old FastAPI app under `/lld-generator/api`, errors as `{"detail": ...}` | Business rules |

The Word engine was moved unchanged (first commit on the branch is the plain copy). A golden check generated the same index with the old app and with Keystone: every XML part of the two documents is identical apart from relationship ids.

## Review, pictures, release history

* **Review** counts chapters done, to finish and empty, and lists every picture still to upload and every table or text that still says TBD; a click opens the chapter.
* **Pictures**: drop, paste or choose in a picture block. SVG files are drawn to PNG in the browser (Word takes no SVG). The **Pictures** button takes several files and puts each into the empty picture whose chapter title or caption shares the most words with the file name.
* **Release History**: changing the version in Project settings adds a row (version, date, writer, Revised, change note); Generate writes all rows into the master template's Release History table.

## Approvers (Document Approval)

Project settings has an **Approvers** list: name, title and company per person, Customer or Multipolar. Generate rebuilds the two Document Approval tables from it, one row per person (company blank = the project's Client, so a client rename follows). Customer approvers are remembered per customer (table `lld_gen_approver_book`): the next project for that customer starts with them. Multipolar approvers come from a default list (Section Head, Network Engineer = Prepared by, Project Manager) that "Use these Multipolar approvers for new projects" replaces. Date and signature stay empty.

## Update mode (re-import)

Chapters are matched by their title path. Tables and paragraphs take the new data; uploaded pictures stay; text typed by hand stays when the index only has `TBD`; chapters that are not in the new index (an appendix written by hand) stay after the ones from the index. A failure halfway changes nothing.

## Master template

`core/docgen/master/LLD Master Template.docx` is registered automatically the first time the Templates list is opened. Made from the LLD Wireless Network Improvement with `core/docgen/master/make_master.py` (cover, footer, Document Control and Document Acceptance as placeholders; chapter content removed). Other templates can be uploaded; a Heading 1 named Document Acceptance (or Penutup, Lembar Pengesahan, Approval) becomes the closing heading.

## Import from the old Document Generator

**Import from the old Document Generator** (top right of the page) finds `../Document_Generator/lld_generator_v*/backend/storage/app.db` or takes a folder, and copies templates, projects, chapters, blocks and images. The old database is opened read-only. Projects and templates remember their old id, so a second run only adds new ones.

## API

`/lld-generator/api/...`: `templates` (GET, POST multipart, GET/PUT/DELETE `/{id}`), `projects` (GET, POST, GET/PUT/DELETE `/{id}`), `projects/{id}/chapters` (GET, POST), `chapters/{id}` (PUT, DELETE, POST `/move`), `chapters/{id}/blocks` (GET, POST), `blocks/{id}` (PUT, DELETE), `projects/{id}/upload-image`, `projects/{id}/images/{file}`, `projects/{id}/import-excel`, `projects/{id}/review`, `projects/{id}/generate`, `download/{file}`, `from-index`, `legacy`, `legacy-import`.

## Not cached

Single user, local SQLite, a few hundred rows per project: every request reads the database directly and nothing is cached, so there is nothing to invalidate. Generated files are the only derived data; they are kept 7 days for the download and removed on the next Generate after that.
