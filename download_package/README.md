# LLM Text Guard - Complete Source Code

## Project Structure
```
├── backend/
│   ├── server.py          # FastAPI backend with all detection logic
│   ├── requirements.txt   # Python dependencies
│   └── .env.example       # Environment variables template
└── frontend/
    ├── app/
    │   └── index.tsx      # Main React Native/Expo app
    └── package.json       # Node.js dependencies
```

## Backend Setup (Self-Hosted)

### 1. Install Python dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Setup MongoDB
- Option A: Install MongoDB locally
- Option B: Use MongoDB Atlas (cloud)

### 3. Configure environment
```bash
cp .env.example .env
# Edit .env with your MongoDB URL
```

### 4. Run the server
```bash
uvicorn server:app --host 0.0.0.0 --port 8001
```

## Frontend Setup

### 1. Install dependencies
```bash
cd frontend
npm install
# or
yarn install
```

### 2. Update API URL
In `app/index.tsx`, change:
```javascript
const API_URL = process.env.EXPO_PUBLIC_BACKEND_URL;
```
to your backend URL:
```javascript
const API_URL = 'https://your-backend-url.com';
```

### 3. Run development
```bash
npx expo start
```

### 4. Build for Google Play
```bash
eas build --platform android
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/scan | POST | Scan text for threats |
| /api/clean | POST | Clean text and remove threats |
| /api/history | GET | Get scan history |
| /api/techniques | GET | List detection techniques |
| /api/history | DELETE | Clear scan history |

## Detection Capabilities

- Zero-width characters (U+200B, U+200C, U+200D, etc.)
- Bidirectional overrides (RTL/LTR attacks)
- Homoglyphs (Cyrillic/Greek lookalikes)
- Control characters
- ASCII smuggling (Unicode tags)
- Instruction injection patterns
- Base64 encoded payloads (recursive, up to 5 layers)
- Hex encoded payloads
- ROT13 encoded payloads
- Delimiter injection

## License
Your code - use as you wish!
