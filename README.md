# MindMap

MindMap is an editable assessment, progress and study-guidance application for AKTU BTech 2nd Year CS & Allied students. It includes a student experience and a protected `/admin` CMS for the syllabus, question bank, and learning resources.

## Local development

Requirements: Node.js 20+ and npm. The app now uses Supabase PostgreSQL and private Supabase Storage in all environments.

1. Create a Supabase project.
2. Copy `.env.example` to `.env` and fill in the Supabase project URL, service-role key, and PostgreSQL **Session Pooler** connection string from the Supabase Dashboard. Keep the service-role key and database password private.
3. Set a random `SESSION_SECRET` (at least 32 characters), `ADMIN_EMAIL`, and `ADMIN_PASSWORD` (at least 12 characters).
4. Run `npm install` and `npm start`.

The app creates the database schema and private `mindmap-resources` Storage bucket on startup, then seeds the syllabus from `data/syllabus.json`. The Supabase database connection is server-side only. Application tables have row-level security enabled and no browser access policies. The Storage bucket is private; files are served through authenticated app routes after publication checks.

Student app: `http://localhost:3000`. Admin panel: `http://localhost:3000/admin` after signing in with the bootstrapped administrator. Configure Supabase through environment variables; never commit `.env` or put the service-role key in frontend code.

## Student workflow

Register/login → select subject and unit → set topic coverage Yes/No and an optional note → create an assessment from selected studied topics → review results and explanations → inspect performance, history, guidance and published resources. Topics marked No or topics with no attempts are not scored as zero.

## Administrator workflow

The initial administrator is created once from `ADMIN_EMAIL` and `ADMIN_PASSWORD` when the app first starts. Visit `/admin` to manage the syllabus, question bank, students, and learning resources. Resources can be linked or uploaded, tagged, searched, previewed, edited, replaced, archived or published. Only published student-visible resources appear in the student catalog. Uploads are validated and limited to 20 MB by default.

The supplied syllabus is the source for the default academic structure. Questions and external resource URLs are not fabricated or preloaded.

## Publish for free

This repository includes a Render Blueprint in `render.yaml` for the web service and uses Supabase for durable database, sessions, and private file storage. No app data is written to the Render filesystem.

1. Push this project to a GitHub repository you control.
2. Create a Supabase project and copy its project URL, server-only service-role key, and **Session Pooler** database URI (the pooler URI uses port 5432).
3. In Render, choose **New → Blueprint**, connect the repository, and apply `render.yaml`.
4. Add the following private values to the Render service environment: `DATABASE_URL`, `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD`. Render generates `SESSION_SECRET` from the Blueprint.
5. Deploy, wait for `/api/health` to report `status: ok`, then check administrator sign-in, student registration, topic coverage, assessment creation/submission, and resource upload/download before inviting students.

The schema migration runs at app startup, so no browser-exposed database key or manual schema paste is required. Render Free web services sleep when idle and Supabase Free projects may pause after a week with very low activity. Free plans have resource limits and do not provide a production availability commitment; review provider limits and configure backups before relying on the service for important records. Keep backups in a location independent of the app host and periodically verify restoration.

Student registration is public by design. Student progress and assessment history are scoped to the signed-in account. The admin console and all private APIs require authentication and role checks.

More project material: [hosting notes](docs/PHASE2_HOSTING.md), [syllabus source](docs/Syllabus_merged.pdf).
