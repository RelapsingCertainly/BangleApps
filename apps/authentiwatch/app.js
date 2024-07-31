const COUNTER_TRIANGLE_SIZE = 10;
const TOKEN_EXTRA_HEIGHT = 16;
const TOKEN_DIGITS_HEIGHT = 30;
const TOKEN_HEIGHT = TOKEN_DIGITS_HEIGHT + TOKEN_EXTRA_HEIGHT;
const PROGRESSBAR_HEIGHT = 3;
const IDLE_REPEATS = 1; // when idle, the number of extra timed periods to show before hiding
const SETTINGS = "authentiwatch.json";
const PIN = "1234"; // Define your PIN here

// Hash functions
const crypto = require("crypto");
const algos = {
  "SHA512": { sha: crypto.SHA512, retsz: 64, blksz: 128 },
  "SHA256": { sha: crypto.SHA256, retsz: 32, blksz: 64 },
  "SHA1": { sha: crypto.SHA1, retsz: 20, blksz: 64 },
};

const CALCULATING = "Calculating";
const NO_TOKENS = "No tokens";
const NOT_SUPPORTED = "Not supported";

var settings = require("Storage").readJSON(SETTINGS, true) || { tokens: [], misc: {} };
if (settings.data) tokens = settings.data; /* v0.02 settings */
if (settings.tokens) tokens = settings.tokens; /* v0.03+ settings */

var enteredPin = "";
var isAuthenticated = false;

function b32decode(seedstr) {
  // RFC4648 Base16/32/64 Data Encodings
  let buf = 0, bitcount = 0, retstr = "";
  for (let c of seedstr.toUpperCase()) {
    if (c == '0') c = 'O';
    if (c == '1') c = 'I';
    if (c == '8') c = 'B';
    c = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c);
    if (c != -1) {
      buf <<= 5;
      buf |= c;
      bitcount += 5;
      if (bitcount >= 8) {
        retstr += String.fromCharCode(buf >> (bitcount - 8));
        buf &= (0xFF >> (16 - bitcount));
        bitcount -= 8;
      }
    }
  }
  let retbuf = new Uint8Array(retstr.length);
  for (let i in retstr) {
    retbuf[i] = retstr.charCodeAt(i);
  }
  return retbuf;
}

function hmac(key, message, algo) {
  let a = algos[algo.toUpperCase()];
  // RFC2104 HMAC
  if (key.length > a.blksz) {
    key = a.sha(key);
  }
  let istr = new Uint8Array(a.blksz + message.length);
  let ostr = new Uint8Array(a.blksz + a.retsz);
  for (let i = 0; i < a.blksz; ++i) {
    let c = (i < key.length) ? key[i] : 0;
    istr[i] = c ^ 0x36;
    ostr[i] = c ^ 0x5C;
  }
  istr.set(message, a.blksz);
  ostr.set(a.sha(istr), a.blksz);
  let ret = a.sha(ostr);
  // RFC4226 HOTP (dynamic truncation)
  let v = new DataView(ret, ret[ret.length - 1] & 0x0F, 4);
  return v.getUint32(0) & 0x7FFFFFFF;
}

function formatOtp(otp, digits) {
  // add 0 padding
  let ret = "" + otp % Math.pow(10, digits);
  while (ret.length < digits) {
    ret = "0" + ret;
  }
  // add a space after every 3rd or 4th digit
  let re = (digits % 3 == 0 || (digits % 3 >= digits % 4 && digits % 4 != 0)) ? "" : ".";
  return ret.replace(new RegExp("(..." + re + ")", "g"), "$1 ").trim();
}

function hotp(token) {
  let d = Date.now();
  let tick, next;
  if (token.period > 0) {
    // RFC6238 - timed
    tick = Math.floor(Math.floor(d / 1000) / token.period);
    next = (tick + 1) * token.period * 1000;
  } else {
    // RFC4226 - counter
    tick = -token.period;
    next = d + 30000;
  }
  let msg = new Uint8Array(8);
  let v = new DataView(msg.buffer);
  v.setUint32(0, tick >> 16 >> 16);
  v.setUint32(4, tick & 0xFFFFFFFF);
  let ret;
  try {
    ret = hmac(b32decode(token.secret), msg, token.algorithm);
    ret = formatOtp(ret, token.digits);
  } catch (err) {
    ret = NOT_SUPPORTED;
  }
  return { hotp: ret, next: next };
}

// Tokens are displayed in three states:
// 1. Unselected (state.id<0)
// 2. Selected, inactive (no code) (state.id>=0,state.hotp.hotp=="")
// 3. Selected, active (code showing) (state.id>=0,state.hotp.hotp!="")
var fontszCache = {};
var state = {
  listy: 0, // list scroll position
  id: -1, // current token ID
  hotp: { hotp: "", next: 0 }
};

function sizeFont(id, txt, w) {
  let sz = fontszCache[id];
  if (!sz) {
    sz = TOKEN_DIGITS_HEIGHT;
    do {
      g.setFont("Vector", sz--);
    } while (g.stringWidth(txt) > w);
    fontszCache[id] = ++sz;
  }
  g.setFont("Vector", sz);
}

function tokenY(id) {
  return id * TOKEN_HEIGHT + AR.y - state.listy;
}

function half(n) {
  return Math.floor(n / 2);
}

function timerCalc() {
  let timerfn = exitApp;
  let timerdly = 10000;
  if (state.id >= 0 && state.hotp.hotp != "") {
    if (tokens[state.id].period > 0) {
      // timed HOTP
      if (state.hotp.next < Date.now()) {
        if (state.cnt > 0) {
          state.cnt--;
          state.hotp = hotp(tokens[state.id]);
        } else {
          state.hotp.hotp = "";
        }
        timerdly = 1;
        timerfn = updateCurrentToken;
      } else {
        timerdly = 1000;
        timerfn = updateProgressBar;
      }
    } else {
      // counter HOTP
      if (state.cnt > 0) {
        state.cnt--;
        timerdly = 30000;
      } else {
        state.hotp.hotp = "";
        timerdly = 1;
      }
      timerfn = updateCurrentToken;
    }
  }
  if (state.drawtimer) {
    clearTimeout(state.drawtimer);
  }
  state.drawtimer = setTimeout(timerfn, timerdly);
}

function updateCurrentToken() {
  drawToken(state.id);
  timerCalc();
}

function updateProgressBar() {
  drawProgressBar();
  timerCalc();
}

function drawProgressBar() {
  let id = state.id;
  if (id >= 0 && tokens[id].period > 0) {
    let rem = Math.min(tokens[id].period, Math.floor((state.hotp.next - Date.now()) / 1000));
    if (rem >= 0) {
      let y1 = tokenY(id);
      let y2 = y1 + TOKEN_HEIGHT - 1;
      if (y2 >= AR.y && y1 <= AR.y2) {
        // token visible
        y1 = y2 - PROGRESSBAR_HEIGHT;
        if (y1 <= AR.y2) {
          // progress bar visible
          y2 = Math.min(y2, AR.y2);
          let xr = Math.floor(AR.w * rem / tokens[id].period) + AR.x;
          g.setColor(g.theme.fgH)
           .setBgColor(g.theme.bgH)
           .fillRect(AR.x, y1, xr, y2)
           .clearRect(xr + 1, y1, AR.x2, y2);
        }
      } else {
        // token not visible
        state.id = -1;
      }
    }
  }
}

// id = token ID number (0...)
function drawToken(id) {
  let x1 = AR.x;
  let y1 = tokenY(id);
  let x2 = AR.x2;
  let y2 = y1 + TOKEN_HEIGHT - 1;
  let lbl = (id >= 0 && id < tokens.length) ? tokens[id].label.substr(0, 10) : "";
  let adj;
  g.setClipRect(x1, Math.max(y1, AR.y), x2, Math.min(y2, AR.y2));
  if (id === state.id) {
    g.setColor(g.theme.fgH)
     .setBgColor(g.theme.bgH)
     .fillRect(x1, y1, x2, y2);
    g.setColor(g.theme.bgH)
     .setBgColor(g.theme.fgH)
     .drawString(lbl, (AR.x2 - g.stringWidth(lbl)) / 2, y1 + TOKEN_DIGITS_HEIGHT / 2 + 1);
    g.setColor(g.theme.bgH);
  } else {
    g.setColor(g.theme.fgL);
    g.drawString(lbl, (AR.x2 - g.stringWidth(lbl)) / 2, y1 + TOKEN_DIGITS_HEIGHT / 2 + 1);
    g.setColor(g.theme.bgH);
  }
  // Draw token digits
  if (id >= 0) {
    let code = state.hotp.hotp;
    if (state.id == id && tokens[id].period > 0) {
      // Draw time remaining if it's a timed token
      code = CALCULATING;
    }
    sizeFont(id, code, AR.w);
    g.drawString(code, (AR.x2 - g.stringWidth(code)) / 2, y1 + TOKEN_DIGITS_HEIGHT + 1);
  } else {
    g.setColor(g.theme.bgH);
    g.drawString(NO_TOKENS, (AR.x2 - g.stringWidth(NO_TOKENS)) / 2, y1 + TOKEN_DIGITS_HEIGHT + 1);
  }
  g.reset();
}

function tokenSelect(id) {
  if (id >= 0 && id < tokens.length) {
    state.id = id;
    state.hotp = hotp(tokens[id]);
    state.cnt = 1;
    timerCalc();
  } else {
    state.id = -1;
    state.hotp = { hotp: "", next: 0 };
    drawToken(-1);
  }
}

function onTouch(e) {
  if (!isAuthenticated) {
    return; // Prevent interaction until authenticated
  }
  let y = e.y - AR.y;
  if (e.y >= AR.y && e.y <= AR.y2) {
    let id = Math.floor(y / TOKEN_HEIGHT);
    if (id >= 0 && id < tokens.length) {
      state.listy = Math.max(id * TOKEN_HEIGHT - AR.y, 0);
      tokenSelect(id);
    } else {
      tokenSelect(-1);
    }
  }
}

function onSwipe(e) {
  if (!isAuthenticated) {
    return; // Prevent interaction until authenticated
  }
  if (e.x < 0) {
    // Swipe Left
    state.listy += TOKEN_HEIGHT;
  } else {
    // Swipe Right
    state.listy -= TOKEN_HEIGHT;
  }
  state.listy = Math.max(0, Math.min(state.listy, (tokens.length - 1) * TOKEN_HEIGHT));
  drawToken(state.id);
}

function showPinEntry() {
  enteredPin = ""; // Reset the PIN entry
  g.clear();
  g.setFont("6x8");
  g.drawString("Enter PIN:", 20, 20);
  
  function handleKeyPress(key) {
    if (key >= 0 && key <= 9) {
      enteredPin += key;
      g.clear();
      g.drawString("Enter PIN: " + enteredPin, 20, 20);
      
      if (enteredPin.length === 4) { // Check if PIN length is correct
        checkPin();
      }
    }
  }

  Bangle.on('accel', function(accel) {
    let key = Math.floor(accel.x / 10); // Simplified example
    handleKeyPress(key);
  });
}

function checkPin() {
  if (enteredPin === PIN) {
    isAuthenticated = true;
    g.clear();
    g.drawString("Access Granted", 20, 20);
    // Proceed to the main app
    setTimeout(startApp, 1000); // Wait a second before starting
  } else {
    g.clear();
    g.drawString("Access Denied", 20, 20);
    // Optionally, restart PIN entry or handle failed attempts
  }
}

function startApp() {
  Bangle.setUI("updown", { up: onTouch, down: onSwipe });
  state.listy = 0;
  drawToken(state.id);
  timerCalc();
}

function initApp() {
  if (isAuthenticated) {
    startApp();
  } else {
    showPinEntry(); // Show PIN entry screen
  }
}

// Initialize the app
initApp();
