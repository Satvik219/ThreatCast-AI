# Free deployment: Vercel + Render + Neo4j AuraDB

This application uses three services. Vercel serves the React UI, Render runs
the FastAPI container, and AuraDB provides the hosted Neo4j database. Do not
place database passwords or Aura connection strings in Git.

## 1. Create a Neo4j AuraDB Free instance

1. Sign in at [Neo4j Aura](https://console.neo4j.io/).
2. Create an **AuraDB Free** instance and wait until it is running.
3. Download the connection details. Keep the `neo4j+s://...` URI and generated
   password private. The username is normally `neo4j` and the database is
   normally `neo4j`.

## 2. Deploy the API on Render

1. Sign in at [Render](https://dashboard.render.com/) using the GitHub account
   that can access this repository.
2. Select **New > Blueprint**, choose this repository, and select `main`.
   Render detects the root `render.yaml` file.
3. For the prompted secret values, enter:
   - `NEO4J_URI`: Aura's `neo4j+s://...` connection URI.
   - `NEO4J_PASSWORD`: Aura's generated password.
   - `CORS_ALLOWED_ORIGINS`: temporarily enter `https://placeholder.vercel.app`.
4. Create the Blueprint and wait for the first deployment and initial graph
   import to complete. Copy the resulting API URL, for example
   `https://threatcast-api.onrender.com`.

## 3. Deploy the frontend on Vercel

1. Sign in at [Vercel](https://vercel.com/) and choose **Add New > Project**.
2. Import `Satvik219/ThreatCast-AI` and set **Root Directory** to `frontend`.
3. Add the production environment variable:
   - `VITE_API_URL`: the Render API URL from step 2, with no trailing slash.
4. Deploy. Copy the generated `https://<project>.vercel.app` URL.

## 4. Allow the Vercel site to call the API

1. Open the Render service's **Environment** settings.
2. Replace `CORS_ALLOWED_ORIGINS` with the Vercel production URL. Add preview
   domains comma-separated if you need them.
3. Save the environment variable and redeploy the Render service.

## 5. Verify

1. Open `https://<render-service>.onrender.com/api/health`; it should return
   `"status": "healthy"`.
2. Open the Vercel URL and confirm the dashboard loads without browser console
   CORS errors.

Render's free web services spin down after inactivity, so the first request
after a quiet period can take about a minute. For every later frontend change,
push to `main`; Vercel automatically rebuilds. Render rebuilds when backend,
Docker, or `render.yaml` files change.
