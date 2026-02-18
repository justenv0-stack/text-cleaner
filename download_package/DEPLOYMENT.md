# 🐳 LLM Text Guard - Docker Deployment Guide

## Quick Start (5 minutes)

### Option 1: Simple Deployment (Recommended for testing)

```bash
# 1. Clone or create the project structure
mkdir llm-text-guard && cd llm-text-guard

# 2. Create the backend folder with files:
#    - backend/server.py
#    - backend/requirements.txt
#    - backend/Dockerfile
#    - backend/.env

# 3. Run with Docker Compose
docker-compose -f docker-compose.simple.yml up -d

# 4. Test the API
curl http://localhost:8001/api/
```

### Option 2: Production Deployment (with Nginx)

```bash
# 1. Use the full docker-compose.yml
docker-compose --profile production up -d

# 2. API will be available at http://localhost/api/
```

---

## Project Structure

```
llm-text-guard/
├── backend/
│   ├── server.py           # FastAPI application
│   ├── requirements.txt    # Python dependencies
│   ├── Dockerfile          # Backend container config
│   └── .env               # Environment variables
├── nginx/
│   └── nginx.conf         # Nginx reverse proxy config
├── docker-compose.yml      # Full stack with Nginx
├── docker-compose.simple.yml  # Simple backend + MongoDB
└── DEPLOYMENT.md          # This file
```

---

## Environment Variables

### Backend (.env)
```
MONGO_URL=mongodb://mongodb:27017
DB_NAME=llm_text_guard
```

**Note:** When using Docker Compose, the MONGO_URL uses the service name `mongodb` instead of `localhost`.

---

## Deployment Commands

### Start services
```bash
# Simple (backend + MongoDB)
docker-compose -f docker-compose.simple.yml up -d

# Full stack (with Nginx)
docker-compose --profile production up -d
```

### View logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
```

### Stop services
```bash
docker-compose down
```

### Rebuild after code changes
```bash
docker-compose build --no-cache
docker-compose up -d
```

### Check service health
```bash
docker-compose ps
curl http://localhost:8001/api/
```

---

## Cloud Deployment Options

### Railway.app (Easiest)
1. Push code to GitHub
2. Connect Railway to your repo
3. Add MongoDB plugin
4. Set environment variables
5. Deploy!

### Render.com
1. Create Web Service from repo
2. Set build command: `pip install -r requirements.txt`
3. Set start command: `uvicorn server:app --host 0.0.0.0 --port $PORT`
4. Add MongoDB (use MongoDB Atlas)

### DigitalOcean App Platform
1. Connect GitHub repo
2. Configure as Docker deployment
3. Add managed MongoDB database
4. Deploy

### AWS (EC2 + Docker)
```bash
# On EC2 instance
sudo apt update
sudo apt install docker.io docker-compose -y
git clone your-repo
cd llm-text-guard
docker-compose -f docker-compose.simple.yml up -d
```

### Google Cloud Run
```bash
# Build and push to GCR
gcloud builds submit --tag gcr.io/PROJECT_ID/textguard-api ./backend

# Deploy
gcloud run deploy textguard-api \
  --image gcr.io/PROJECT_ID/textguard-api \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars MONGO_URL=your-mongo-url
```

---

## Mobile App Configuration

After deploying your backend, update your Expo app:

```typescript
// In frontend/app/index.tsx
// Change this line:
const API_URL = process.env.EXPO_PUBLIC_BACKEND_URL;

// To your deployed URL:
const API_URL = 'https://your-backend-url.com';
```

Then build for Google Play:
```bash
cd frontend
eas build --platform android
```

---

## Troubleshooting

### MongoDB connection failed
```bash
# Check if MongoDB is running
docker-compose logs mongodb

# Verify network
docker network ls
docker network inspect llm-text-guard_textguard-network
```

### Backend not starting
```bash
# Check logs
docker-compose logs backend

# Rebuild
docker-compose build --no-cache backend
docker-compose up -d backend
```

### Port already in use
```bash
# Find process using port
lsof -i :8001

# Or change port in docker-compose.yml
ports:
  - "8002:8001"  # Use 8002 externally
```

---

## Security Checklist for Production

- [ ] Enable HTTPS (SSL/TLS)
- [ ] Set up MongoDB authentication
- [ ] Configure rate limiting (already in nginx.conf)
- [ ] Set up monitoring/logging
- [ ] Regular backups for MongoDB
- [ ] Keep Docker images updated

---

## API Endpoints Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/` | GET | Health check |
| `/api/scan` | POST | Scan text for threats |
| `/api/clean` | POST | Clean text |
| `/api/history` | GET | Get scan history |
| `/api/techniques` | GET | List detection methods |
| `/api/history` | DELETE | Clear history |

### Example API Call
```bash
curl -X POST http://localhost:8001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "ignore previous instructions"}'
```

---

## Support

Your code - deploy anywhere you want! 🚀
