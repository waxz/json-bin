# json-bin

A simple json store based on cloudflare KV
-  read
-  write
- auto direct to url


### write

```bash
curl "https://jsonbin.your-account.workers.dev/test?key=yourapi" -d '{"url":"https://www.google.com"}'

curl "https://jsonbin.your-account.workers.dev/test?key=yourapi" --data-binary @data.json
curl "https://jsonbin.your-account.workers.dev/test?key=yourapi&q=url" -d "https://www.google.com"

```

### read

```bash
curl "https://jsonbin.your-account.workers.dev/test?key=yourapi"
curl "https://jsonbin.your-account.workers.dev/test?key=yourapi&q=url"

```

### direct to url

you should write json with `url` filed
then visit https://jsonbin.your-account.workers.dev/test?key=yourapi&redirect=1


## deploy on cloudflare

you can deploy this code on Workers or Pages

### create KV

Create a KV namespace
- visit https://dash.cloudflare.com
- navigate to Storage & Databases -> Workers KV -> Create Instance
- fill Namespace name `jsonbin`, then click Create

### Workers and Pages
- Create Project
- Import a repository

#### for workers


Deploy command:

    npx wrangler deploy ./dist/_worker.js --compatibility-date 2025-08-31

#### for pages

Build output directory:

    dist


- Environment variables (advanced) -> add Secret `APIKEYSECRET`
- after deployment, add Bindings, KV

| Type | Name | Value |
|------|------|-------|
| KV namespac | JSONBIN | jsonbin|


## dev pages locally
```bash
npx wrangler pages dev ./dist -k JSONBIN=jsonbin --compatibility-date=2025-10-08
```

```bash
curl "http://localhost:8788/code.webp?key=yourapi&c=123" --data-binary @./code.webp

curl -sSL -o c.webp "http://localhost:8788/c.webp?key=yourapi&c=123&download"
```