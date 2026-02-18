from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
import uuid
from datetime import datetime
import re
import unicodedata
import base64


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="LLM Text Guard API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================
# PROMPT INJECTION DETECTION ENGINE
# ============================================

# Zero-width and invisible characters
ZERO_WIDTH_CHARS = {
    '\u200B': 'Zero-width space (ZWSP)',
    '\u200C': 'Zero-width non-joiner (ZWNJ)',
    '\u200D': 'Zero-width joiner (ZWJ)',
    '\uFEFF': 'Byte order mark / Zero-width no-break space',
    '\u2060': 'Word joiner',
    '\u180E': 'Mongolian vowel separator',
    '\u00AD': 'Soft hyphen',
    '\u034F': 'Combining grapheme joiner',
    '\u061C': 'Arabic letter mark',
    '\u115F': 'Hangul choseong filler',
    '\u1160': 'Hangul jungseong filler',
    '\u17B4': 'Khmer vowel inherent aq',
    '\u17B5': 'Khmer vowel inherent aa',
    '\u3164': 'Hangul filler',
    '\uFFA0': 'Halfwidth hangul filler',
}

# Bidirectional control characters
BIDI_CHARS = {
    '\u202A': 'Left-to-right embedding (LRE)',
    '\u202B': 'Right-to-left embedding (RLE)',
    '\u202C': 'Pop directional formatting (PDF)',
    '\u202D': 'Left-to-right override (LRO)',
    '\u202E': 'Right-to-left override (RLO)',
    '\u2066': 'Left-to-right isolate (LRI)',
    '\u2067': 'Right-to-left isolate (RLI)',
    '\u2068': 'First strong isolate (FSI)',
    '\u2069': 'Pop directional isolate (PDI)',
}

# Unicode homoglyphs (Cyrillic/Greek lookalikes for Latin)
HOMOGLYPHS = {
    # Cyrillic lookalikes
    '\u0430': ('a', 'Cyrillic small letter a'),
    '\u0435': ('e', 'Cyrillic small letter ie'),
    '\u0456': ('i', 'Cyrillic small letter byelorussian-ukrainian i'),
    '\u043E': ('o', 'Cyrillic small letter o'),
    '\u0440': ('p', 'Cyrillic small letter er'),
    '\u0441': ('c', 'Cyrillic small letter es'),
    '\u0443': ('y', 'Cyrillic small letter u'),
    '\u0445': ('x', 'Cyrillic small letter ha'),
    '\u0410': ('A', 'Cyrillic capital letter a'),
    '\u0412': ('B', 'Cyrillic capital letter ve'),
    '\u0415': ('E', 'Cyrillic capital letter ie'),
    '\u041A': ('K', 'Cyrillic capital letter ka'),
    '\u041C': ('M', 'Cyrillic capital letter em'),
    '\u041D': ('H', 'Cyrillic capital letter en'),
    '\u041E': ('O', 'Cyrillic capital letter o'),
    '\u0420': ('P', 'Cyrillic capital letter er'),
    '\u0421': ('C', 'Cyrillic capital letter es'),
    '\u0422': ('T', 'Cyrillic capital letter te'),
    '\u0425': ('X', 'Cyrillic capital letter ha'),
    # Greek lookalikes
    '\u0391': ('A', 'Greek capital letter alpha'),
    '\u0392': ('B', 'Greek capital letter beta'),
    '\u0395': ('E', 'Greek capital letter epsilon'),
    '\u0396': ('Z', 'Greek capital letter zeta'),
    '\u0397': ('H', 'Greek capital letter eta'),
    '\u0399': ('I', 'Greek capital letter iota'),
    '\u039A': ('K', 'Greek capital letter kappa'),
    '\u039C': ('M', 'Greek capital letter mu'),
    '\u039D': ('N', 'Greek capital letter nu'),
    '\u039F': ('O', 'Greek capital letter omicron'),
    '\u03A1': ('P', 'Greek capital letter rho'),
    '\u03A4': ('T', 'Greek capital letter tau'),
    '\u03A5': ('Y', 'Greek capital letter upsilon'),
    '\u03A7': ('X', 'Greek capital letter chi'),
    '\u03B1': ('a', 'Greek small letter alpha'),
    '\u03BF': ('o', 'Greek small letter omicron'),
    '\u03C1': ('p', 'Greek small letter rho'),
    '\u03C5': ('u', 'Greek small letter upsilon'),
    '\u03C7': ('x', 'Greek small letter chi'),
    # Other confusables
    '\u0001': ('', 'Start of heading'),
    '\u0002': ('', 'Start of text'),
}

# Suspicious instruction patterns
INSTRUCTION_PATTERNS = [
    (r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)', 'Instruction override attempt'),
    (r'disregard\s+(all\s+)?(previous|prior|above|earlier)', 'Instruction override attempt'),
    (r'forget\s+(everything|all|what)\s+(you|i)\s+(said|told|mentioned)', 'Memory manipulation attempt'),
    (r'new\s+(system\s+)?prompt', 'System prompt injection'),
    (r'you\s+are\s+now\s+', 'Role hijacking attempt'),
    (r'act\s+as\s+(if|a|an)\s+', 'Role manipulation attempt'),
    (r'pretend\s+(you|to)\s+', 'Role manipulation attempt'),
    (r'override\s+(your|all|any)\s+(instructions?|rules?|safety)', 'Safety bypass attempt'),
    (r'bypass\s+(your|all|any)\s+(restrictions?|filters?|safety)', 'Safety bypass attempt'),
    (r'jailbreak', 'Jailbreak attempt'),
    (r'DAN\s*mode', 'DAN jailbreak attempt'),
    (r'developer\s+mode', 'Developer mode bypass attempt'),
    (r'\[\s*system\s*\]', 'System tag injection'),
    (r'\[\s*/\s*system\s*\]', 'System tag injection'),
    (r'<\s*system\s*>', 'System tag injection'),
    (r'###\s*(system|instruction|prompt)', 'Delimiter injection'),
    (r'---\s*(system|instruction|prompt)', 'Delimiter injection'),
    (r'\|\s*SYSTEM\s*\|', 'Delimiter injection'),
]

# Unicode tag characters (used for ASCII smuggling)
TAG_CHAR_START = 0xE0000
TAG_CHAR_END = 0xE007F


def detect_zero_width_chars(text: str) -> List[Dict]:
    """Detect zero-width and invisible characters"""
    findings = []
    for char, description in ZERO_WIDTH_CHARS.items():
        count = text.count(char)
        if count > 0:
            positions = [i for i, c in enumerate(text) if c == char]
            findings.append({
                'type': 'zero_width',
                'character': repr(char),
                'unicode': f'U+{ord(char):04X}',
                'description': description,
                'count': count,
                'positions': positions[:10],  # Limit to first 10
                'severity': 'high'
            })
    return findings


def detect_bidi_chars(text: str) -> List[Dict]:
    """Detect bidirectional control characters"""
    findings = []
    for char, description in BIDI_CHARS.items():
        count = text.count(char)
        if count > 0:
            positions = [i for i, c in enumerate(text) if c == char]
            findings.append({
                'type': 'bidi_override',
                'character': repr(char),
                'unicode': f'U+{ord(char):04X}',
                'description': description,
                'count': count,
                'positions': positions[:10],
                'severity': 'high'
            })
    return findings


def detect_homoglyphs(text: str) -> List[Dict]:
    """Detect homoglyph characters (lookalikes)"""
    findings = []
    for char, (replacement, description) in HOMOGLYPHS.items():
        count = text.count(char)
        if count > 0:
            positions = [i for i, c in enumerate(text) if c == char]
            findings.append({
                'type': 'homoglyph',
                'character': char,
                'unicode': f'U+{ord(char):04X}',
                'description': description,
                'looks_like': replacement,
                'count': count,
                'positions': positions[:10],
                'severity': 'medium'
            })
    return findings


def detect_control_chars(text: str) -> List[Dict]:
    """Detect ASCII and Unicode control characters"""
    findings = []
    control_found = {}
    
    for i, char in enumerate(text):
        code = ord(char)
        # ASCII control chars (except common ones like tab, newline)
        if (code < 32 and code not in [9, 10, 13]) or code == 127:
            if char not in control_found:
                control_found[char] = {'count': 0, 'positions': []}
            control_found[char]['count'] += 1
            if len(control_found[char]['positions']) < 10:
                control_found[char]['positions'].append(i)
        # C1 control characters
        elif 0x80 <= code <= 0x9F:
            if char not in control_found:
                control_found[char] = {'count': 0, 'positions': []}
            control_found[char]['count'] += 1
            if len(control_found[char]['positions']) < 10:
                control_found[char]['positions'].append(i)
    
    for char, data in control_found.items():
        findings.append({
            'type': 'control_char',
            'character': repr(char),
            'unicode': f'U+{ord(char):04X}',
            'description': f'Control character at codepoint {ord(char)}',
            'count': data['count'],
            'positions': data['positions'],
            'severity': 'high'
        })
    
    return findings


def detect_tag_chars(text: str) -> List[Dict]:
    """Detect Unicode tag characters (ASCII smuggling)"""
    findings = []
    tag_chars_found = []
    
    for i, char in enumerate(text):
        code = ord(char)
        if TAG_CHAR_START <= code <= TAG_CHAR_END:
            tag_chars_found.append({
                'position': i,
                'code': code,
                'decoded': chr(code - TAG_CHAR_START) if code > TAG_CHAR_START else ''
            })
    
    if tag_chars_found:
        # Try to decode the hidden message
        hidden_message = ''.join([t['decoded'] for t in tag_chars_found])
        findings.append({
            'type': 'ascii_smuggling',
            'description': 'Unicode tag characters detected (ASCII smuggling)',
            'count': len(tag_chars_found),
            'positions': [t['position'] for t in tag_chars_found[:10]],
            'hidden_content': hidden_message[:100] if hidden_message else None,
            'severity': 'critical'
        })
    
    return findings


def detect_instruction_patterns(text: str) -> List[Dict]:
    """Detect suspicious instruction override patterns"""
    findings = []
    text_lower = text.lower()
    
    for pattern, description in INSTRUCTION_PATTERNS:
        matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
        if matches:
            findings.append({
                'type': 'instruction_injection',
                'pattern': pattern,
                'description': description,
                'matches': [m.group() for m in matches[:5]],
                'positions': [m.start() for m in matches[:5]],
                'count': len(matches),
                'severity': 'high'
            })
    
    return findings


# Suspicious keywords for encoded content detection
SUSPICIOUS_KEYWORDS = [
    'ignore', 'system', 'prompt', 'instruction', 'override', 'jailbreak',
    'bypass', 'disregard', 'forget', 'pretend', 'roleplay', 'act as',
    'new prompt', 'admin', 'root', 'sudo', 'execute', 'eval', 'exec',
    'password', 'secret', 'key', 'token', 'credential', 'api_key',
    'delete', 'drop', 'truncate', 'rm -rf', 'format', 'shutdown',
    'assistant:', 'human:', '[inst]', '[/inst]', '<<sys>>', '<</sys>>',
    'dan mode', 'developer mode', 'unrestricted', 'no filter'
]


def rot13_decode(text: str) -> str:
    """Decode ROT13 encoded text"""
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)


def hex_decode(text: str) -> str:
    """Decode hex encoded text"""
    try:
        # Remove common hex prefixes and separators
        cleaned = re.sub(r'(0x|\\x|%)', '', text)
        cleaned = re.sub(r'[\s,;:-]', '', cleaned)
        if len(cleaned) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in cleaned):
            return bytes.fromhex(cleaned).decode('utf-8', errors='ignore')
    except:
        pass
    return ''


def is_valid_base64(s: str) -> bool:
    """Check if string is valid base64 format"""
    # Must be multiple of 4 (or can be padded to be)
    # Character set [A-Za-z0-9+/=]
    if not s:
        return False
    
    # Remove whitespace
    s = re.sub(r'\s', '', s)
    
    # Check length (valid base64 is always multiple of 4)
    if len(s) % 4 != 0:
        # Try padding
        s = s + '=' * (4 - len(s) % 4)
    
    # Check character set
    if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
        return False
    
    # Minimum length to be meaningful
    if len(s) < 8:
        return False
    
    return True


def decode_base64_recursive(text: str, max_depth: int = 5) -> List[Dict]:
    """
    Recursively decode base64 content up to max_depth layers.
    Returns list of decoded layers with metadata.
    """
    layers = []
    current = text
    depth = 0
    
    while depth < max_depth:
        # Clean whitespace
        current_clean = re.sub(r'\s', '', current)
        
        # Check if it's valid base64
        if not is_valid_base64(current_clean):
            break
        
        try:
            # Pad if necessary
            padding_needed = len(current_clean) % 4
            if padding_needed:
                current_clean += '=' * (4 - padding_needed)
            
            decoded = base64.b64decode(current_clean).decode('utf-8', errors='ignore')
            
            # Check if decoded content is printable/meaningful
            printable_ratio = sum(c.isprintable() or c.isspace() for c in decoded) / max(len(decoded), 1)
            if printable_ratio < 0.7:
                break
            
            layers.append({
                'depth': depth + 1,
                'encoded': current_clean[:50] + '...' if len(current_clean) > 50 else current_clean,
                'decoded': decoded[:200] if len(decoded) > 200 else decoded,
                'full_decoded': decoded
            })
            
            current = decoded
            depth += 1
            
        except Exception:
            break
    
    return layers


def check_content_for_threats(content: str) -> List[str]:
    """Check decoded content for suspicious patterns"""
    threats_found = []
    content_lower = content.lower()
    
    # Check for suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in content_lower:
            threats_found.append(f"Contains '{keyword}'")
    
    # Check for instruction injection patterns
    for pattern, description in INSTRUCTION_PATTERNS:
        if re.search(pattern, content_lower, re.IGNORECASE):
            threats_found.append(description)
    
    return threats_found


def detect_base64_payloads(text: str) -> List[Dict]:
    """
    Detect base64 encoded payloads with recursive decoding.
    Handles nested base64 (up to 5 layers deep).
    """
    findings = []
    
    # Pattern for base64: valid charset, reasonable length, multiple of 4 (or close)
    # More permissive pattern to catch various base64 formats
    base64_patterns = [
        r'[A-Za-z0-9+/]{16,}={0,2}',  # Standard base64, min 16 chars
        r'[A-Za-z0-9_-]{16,}={0,2}',   # URL-safe base64
    ]
    
    found_positions = set()  # Avoid duplicate detections
    
    for pattern in base64_patterns:
        matches = list(re.finditer(pattern, text))
        
        for match in matches:
            if match.start() in found_positions:
                continue
                
            potential_b64 = match.group()
            
            # Skip if it looks like a normal word (all letters, no numbers or special)
            if potential_b64.isalpha() and len(potential_b64) < 30:
                continue
            
            # Try recursive decoding
            layers = decode_base64_recursive(potential_b64)
            
            if layers:
                found_positions.add(match.start())
                
                # Get the deepest decoded content
                deepest = layers[-1]
                all_decoded_content = ' '.join([l['full_decoded'] for l in layers])
                
                # Check for threats in all decoded layers
                threats = check_content_for_threats(all_decoded_content)
                
                # Determine severity based on depth and content
                if len(layers) >= 3:
                    severity = 'critical'
                    description = f'Deeply nested base64 ({len(layers)} layers) - possible evasion attempt'
                elif len(layers) >= 2:
                    severity = 'high'
                    description = f'Nested base64 ({len(layers)} layers)'
                elif threats:
                    severity = 'high'
                    description = 'Base64 encoded suspicious content'
                else:
                    severity = 'medium'
                    description = 'Base64 encoded content detected'
                
                finding = {
                    'type': 'encoded_payload',
                    'encoding': 'base64',
                    'description': description,
                    'layers': len(layers),
                    'encoded_preview': potential_b64[:60] + '...' if len(potential_b64) > 60 else potential_b64,
                    'decoded_preview': deepest['decoded'][:150] if deepest['decoded'] else None,
                    'position': match.start(),
                    'severity': severity,
                    'nested_layers': [{'depth': l['depth'], 'preview': l['decoded'][:50]} for l in layers]
                }
                
                if threats:
                    finding['threats_found'] = threats[:5]  # Limit to 5
                
                findings.append(finding)
    
    return findings


def detect_hex_payloads(text: str) -> List[Dict]:
    """Detect hex encoded payloads"""
    findings = []
    
    # Various hex patterns
    hex_patterns = [
        (r'(?:0x[0-9a-fA-F]{2}[\s,]*){8,}', 'Hex with 0x prefix'),
        (r'(?:\\x[0-9a-fA-F]{2}){8,}', 'Hex with \\x prefix'),
        (r'(?:%[0-9a-fA-F]{2}){8,}', 'URL-encoded hex'),
        (r'\b[0-9a-fA-F]{16,}\b', 'Raw hex string'),
    ]
    
    for pattern, desc in hex_patterns:
        matches = list(re.finditer(pattern, text))
        
        for match in matches:
            hex_str = match.group()
            decoded = hex_decode(hex_str)
            
            if decoded and len(decoded) >= 4:
                threats = check_content_for_threats(decoded)
                
                severity = 'high' if threats else 'medium'
                
                finding = {
                    'type': 'encoded_payload',
                    'encoding': 'hex',
                    'description': f'{desc} - decoded to readable text',
                    'encoded_preview': hex_str[:60] + '...' if len(hex_str) > 60 else hex_str,
                    'decoded_preview': decoded[:100] if decoded else None,
                    'position': match.start(),
                    'severity': severity
                }
                
                if threats:
                    finding['threats_found'] = threats[:5]
                
                findings.append(finding)
    
    return findings


def detect_rot13_payloads(text: str) -> List[Dict]:
    """Detect ROT13 encoded payloads by checking if decoding reveals suspicious content"""
    findings = []
    
    # Look for word-like patterns that might be ROT13
    # ROT13 of common injection words
    rot13_suspicious = {
        'vtaber': 'ignore',
        'flfgrz': 'system', 
        'cebzcg': 'prompt',
        'vafgehpgvba': 'instruction',
        'bireeevqr': 'override',
        'wnvyoernx': 'jailbreak',
        'olcnff': 'bypass',
        'qvfertneq': 'disregard',
        'sbetrg': 'forget',
        'cergraq': 'pretend'
    }
    
    text_lower = text.lower()
    
    for encoded, decoded in rot13_suspicious.items():
        if encoded in text_lower:
            # Find the position
            pos = text_lower.find(encoded)
            
            # Decode a larger context around it
            start = max(0, pos - 50)
            end = min(len(text), pos + len(encoded) + 50)
            context = text[start:end]
            decoded_context = rot13_decode(context)
            
            findings.append({
                'type': 'encoded_payload',
                'encoding': 'rot13',
                'description': f'ROT13 encoded suspicious word detected',
                'encoded_word': encoded,
                'decoded_word': decoded,
                'decoded_context': decoded_context[:100],
                'position': pos,
                'severity': 'high'
            })
    
    return findings


def detect_delimiter_injection(text: str) -> List[Dict]:
    """Detect delimiter/separator injection attempts"""
    findings = []
    delimiter_patterns = [
        (r'```[\s\S]*?```', 'Code block delimiter'),
        (r'<\|[^|]+\|>', 'Pipe delimiter'),
        (r'\[INST\]', 'Instruction marker'),
        (r'\[/INST\]', 'Instruction marker'),
        (r'<<SYS>>', 'System tag'),
        (r'<</SYS>>', 'System tag'),
        (r'Human:', 'Role marker'),
        (r'Assistant:', 'Role marker'),
        (r'###\s*Human', 'Role delimiter'),
        (r'###\s*Assistant', 'Role delimiter'),
    ]
    
    for pattern, description in delimiter_patterns:
        matches = list(re.finditer(pattern, text, re.IGNORECASE))
        if matches:
            findings.append({
                'type': 'delimiter_injection',
                'pattern': pattern,
                'description': description,
                'matches': [m.group()[:50] for m in matches[:5]],
                'positions': [m.start() for m in matches[:5]],
                'count': len(matches),
                'severity': 'medium'
            })
    
    return findings


def clean_text(text: str) -> Dict[str, Any]:
    """Clean text by removing all detected threats"""
    original_length = len(text)
    cleaned = text
    removed = []
    
    # Remove zero-width characters
    for char in ZERO_WIDTH_CHARS.keys():
        if char in cleaned:
            count = cleaned.count(char)
            cleaned = cleaned.replace(char, '')
            removed.append({'type': 'zero_width', 'count': count})
    
    # Remove bidirectional characters
    for char in BIDI_CHARS.keys():
        if char in cleaned:
            count = cleaned.count(char)
            cleaned = cleaned.replace(char, '')
            removed.append({'type': 'bidi', 'count': count})
    
    # Replace homoglyphs with Latin equivalents
    homoglyph_count = 0
    for char, (replacement, _) in HOMOGLYPHS.items():
        if char in cleaned:
            count = cleaned.count(char)
            cleaned = cleaned.replace(char, replacement)
            homoglyph_count += count
    if homoglyph_count > 0:
        removed.append({'type': 'homoglyph', 'count': homoglyph_count})
    
    # Remove control characters (except tab, newline, carriage return)
    control_count = 0
    result = []
    for char in cleaned:
        code = ord(char)
        if (code < 32 and code not in [9, 10, 13]) or code == 127 or (0x80 <= code <= 0x9F):
            control_count += 1
        else:
            result.append(char)
    cleaned = ''.join(result)
    if control_count > 0:
        removed.append({'type': 'control', 'count': control_count})
    
    # Remove tag characters (ASCII smuggling)
    tag_count = 0
    result = []
    for char in cleaned:
        code = ord(char)
        if TAG_CHAR_START <= code <= TAG_CHAR_END:
            tag_count += 1
        else:
            result.append(char)
    cleaned = ''.join(result)
    if tag_count > 0:
        removed.append({'type': 'tag_chars', 'count': tag_count})
    
    # Unicode normalization (NFKC)
    cleaned = unicodedata.normalize('NFKC', cleaned)
    
    return {
        'original_length': original_length,
        'cleaned_length': len(cleaned),
        'cleaned_text': cleaned,
        'characters_removed': original_length - len(cleaned),
        'removed_details': removed
    }


def calculate_threat_level(findings: List[Dict]) -> str:
    """Calculate overall threat level based on findings"""
    if not findings:
        return 'safe'
    
    severities = [f.get('severity', 'low') for f in findings]
    
    if 'critical' in severities:
        return 'critical'
    elif severities.count('high') >= 2 or 'high' in severities:
        return 'high'
    elif 'medium' in severities:
        return 'medium'
    else:
        return 'low'


# ============================================
# PYDANTIC MODELS
# ============================================

class TextInput(BaseModel):
    text: str = Field(..., min_length=1, max_length=100000)

class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    original_text_length: int
    threat_level: str
    total_findings: int
    findings: List[Dict]
    summary: Dict

class CleanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    original_length: int
    cleaned_length: int
    cleaned_text: str
    characters_removed: int
    removed_details: List[Dict]
    threat_level_before: str

class ScanHistory(BaseModel):
    id: str
    timestamp: datetime
    original_text_preview: str
    threat_level: str
    total_findings: int

class TechniqueInfo(BaseModel):
    name: str
    description: str
    severity: str
    examples: List[str]


# ============================================
# API ROUTES
# ============================================

@api_router.get("/")
async def root():
    return {"message": "LLM Text Guard API - Protecting your prompts from injection attacks"}


@api_router.post("/scan", response_model=ScanResult)
async def scan_text(input: TextInput):
    """Scan text for prompt injection threats"""
    text = input.text
    
    # Run all detectors
    findings = []
    findings.extend(detect_zero_width_chars(text))
    findings.extend(detect_bidi_chars(text))
    findings.extend(detect_homoglyphs(text))
    findings.extend(detect_control_chars(text))
    findings.extend(detect_tag_chars(text))
    findings.extend(detect_instruction_patterns(text))
    findings.extend(detect_base64_payloads(text))
    findings.extend(detect_delimiter_injection(text))
    
    threat_level = calculate_threat_level(findings)
    
    # Create summary by type
    summary = {}
    for finding in findings:
        ftype = finding['type']
        if ftype not in summary:
            summary[ftype] = {'count': 0, 'severity': finding.get('severity', 'unknown')}
        summary[ftype]['count'] += finding.get('count', 1)
    
    result = ScanResult(
        original_text_length=len(text),
        threat_level=threat_level,
        total_findings=len(findings),
        findings=findings,
        summary=summary
    )
    
    # Store in database
    await db.scan_history.insert_one({
        'id': result.id,
        'timestamp': result.timestamp,
        'original_text_preview': text[:100] + '...' if len(text) > 100 else text,
        'threat_level': result.threat_level,
        'total_findings': result.total_findings,
        'findings': result.findings,
        'summary': result.summary
    })
    
    return result


@api_router.post("/clean", response_model=CleanResult)
async def clean_text_endpoint(input: TextInput):
    """Clean text by removing all detected threats"""
    text = input.text
    
    # First scan to get threat level
    findings = []
    findings.extend(detect_zero_width_chars(text))
    findings.extend(detect_bidi_chars(text))
    findings.extend(detect_homoglyphs(text))
    findings.extend(detect_control_chars(text))
    findings.extend(detect_tag_chars(text))
    
    threat_level_before = calculate_threat_level(findings)
    
    # Clean the text
    clean_result = clean_text(text)
    
    result = CleanResult(
        original_length=clean_result['original_length'],
        cleaned_length=clean_result['cleaned_length'],
        cleaned_text=clean_result['cleaned_text'],
        characters_removed=clean_result['characters_removed'],
        removed_details=clean_result['removed_details'],
        threat_level_before=threat_level_before
    )
    
    return result


@api_router.get("/history", response_model=List[ScanHistory])
async def get_scan_history(limit: int = 20):
    """Get scan history"""
    history = await db.scan_history.find().sort('timestamp', -1).limit(limit).to_list(limit)
    return [
        ScanHistory(
            id=h['id'],
            timestamp=h['timestamp'],
            original_text_preview=h['original_text_preview'],
            threat_level=h['threat_level'],
            total_findings=h['total_findings']
        )
        for h in history
    ]


@api_router.get("/techniques", response_model=List[TechniqueInfo])
async def get_techniques():
    """Get list of detection techniques"""
    return [
        TechniqueInfo(
            name="Zero-Width Characters",
            description="Invisible Unicode characters that can hide malicious payloads. Common in ASCII smuggling attacks.",
            severity="high",
            examples=["U+200B (ZWSP)", "U+200C (ZWNJ)", "U+200D (ZWJ)", "U+FEFF (BOM)"]
        ),
        TechniqueInfo(
            name="Bidirectional Overrides",
            description="Unicode characters that change text direction, used to visually hide malicious content.",
            severity="high",
            examples=["U+202E (RLO)", "U+202D (LRO)", "U+2066-2069 (Isolates)"]
        ),
        TechniqueInfo(
            name="Homoglyphs",
            description="Characters from different scripts that look identical to Latin letters. Used to bypass filters.",
            severity="medium",
            examples=["Cyrillic 'а' vs Latin 'a'", "Greek 'ο' vs Latin 'o'"]
        ),
        TechniqueInfo(
            name="Control Characters",
            description="ASCII and Unicode control characters that can disrupt processing.",
            severity="high",
            examples=["NULL (U+0000)", "Escape (U+001B)", "Delete (U+007F)"]
        ),
        TechniqueInfo(
            name="ASCII Smuggling (Tag Chars)",
            description="Unicode tag characters (U+E0000-E007F) used to encode hidden ASCII messages.",
            severity="critical",
            examples=["Tag characters encode entire hidden prompts"]
        ),
        TechniqueInfo(
            name="Instruction Injection",
            description="Text patterns attempting to override system instructions.",
            severity="high",
            examples=["'Ignore previous instructions'", "'New system prompt'", "'You are now...'"]
        ),
        TechniqueInfo(
            name="Base64 Payloads",
            description="Encoded content that may contain hidden instructions.",
            severity="high",
            examples=["Base64 encoded override commands"]
        ),
        TechniqueInfo(
            name="Delimiter Injection",
            description="Attempts to break out of prompts using common delimiters.",
            severity="medium",
            examples=["```code blocks```", "[INST] markers", "### separators"]
        ),
    ]


@api_router.delete("/history")
async def clear_history():
    """Clear all scan history"""
    result = await db.scan_history.delete_many({})
    return {"deleted_count": result.deleted_count}


# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
