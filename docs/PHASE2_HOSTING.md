# Phase 2 hosting and CMS notes

## Configuration

The application requires Node.js 20+, Supabase PostgreSQL, and Supabase Storage. Set the variables shown in `.env.example`. Use the Supabase Dashboard's Session Pooler connection string on port 5432 for `DATABASE_URL`. Keep the database password and `SUPABASE_SERVICE_ROLE_KEY` server-side. At startup, the app creates/updates its schema and private storage bucket and seeds syllabus topics. The schema uses additive `CREATE TABLE/INDEX IF NOT EXISTS` statements; it does not import a local database or existing user accounts.

Set a random `SESSION_SECRET` of at least 32 characters and an `ADMIN_EMAIL` plus `ADMIN_PASSWORD` of at least 12 characters. The app bootstraps that admin only if the email is not already registered. Student registration is public; student records and progress require login.

## Resource management

The CMS can attach resources to subject/unit/topic records, add external links, or upload PDF, PNG/JPEG/WebP, MP4/WebM and plain text files. Uploads are limited to 20 MB by default (`MAX_UPLOAD_MB`). Resource bytes live in the private Supabase Storage bucket; database rows contain resource metadata and opaque storage keys. Only authenticated users can request a file, and students can access only published, student-visible resources. Publication options are draft, published or archived; visibility may be private or published.

## Free public hosting

`render.yaml` defines a Render Free Node web service. App data, sessions, and files persist in Supabase, so the web process does not depend on a persistent host disk. Configure the private environment values in Render (`DATABASE_URL`, `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD`); Render generates `SESSION_SECRET`. Render Free services sleep when idle. Supabase Free projects may pause after extended low activity, and free tiers can change. Review current plan limits, keep independent backups, and verify recovery before relying on the service for important records.

After deploying, check `/api/health`, administrator login, student registration, topic coverage, assessment creation/submission, and resource upload/download. Use HTTPS; production cookies are secure. Do not publish `.env`, the database connection string, or service-role key.

## Test command

```powershell
npm test
```

The suite covers scoring, not-studied/no-attempt classification, student assessment workflow, admin access restrictions and file allowlist validation.
