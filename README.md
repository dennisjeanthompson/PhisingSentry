# PhishSentry

Real phishing detector with:
- Heuristic URL + text analysis
- Free OpenPhish threat-intel integration (no credit card, no paid API)
- Working frontend + backend API

## Run

```bash
npm install
npm start
```

Open: http://localhost:3000

## API

- `POST /api/analyze-url`
- `POST /api/analyze-text`
- `GET /api/health`

Example:

```bash
curl -X POST http://localhost:3000/api/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```
