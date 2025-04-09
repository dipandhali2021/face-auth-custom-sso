// OAuth 2.0 Server with Face Authentication
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Import MongoDB models and face recognition utilities
const { connectDB, User, FaceProfile, Token, AuthCode } = require('./models/db');
const faceRecognition = require('./utils/faceRecognition');
const cloudinary = require('./utils/cloudinary');

// OAuth clients configuration
const clients = {
  'face-auth-client': {
    clientId: 'face-auth-client',
    clientSecret: '2f4faadac82f1b78aec68aea3de330303f3aa90531222f35e656943e581aa118',
    redirectUris: ['http://localhost:5000/oauth/callback', 'http://localhost:3000/oauth/callback', 'https://dapi.clerk.com/v1/oauth_debug/callback', 'https://143gdh0g-5000.inc1.devtunnels.ms/oauth/callback', 'https://capable-boar-92.clerk.accounts.dev/v1/oauth_callback'],
    grants: ['authorization_code'],
    scopes: ['openid', 'profile']
  }
};

// Create Express app
const app = express();

// Parse command line arguments for port
const args = process.argv.slice(2);
let PORT = 5001;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--port' && i + 1 < args.length) {
    PORT = parseInt(args[i + 1], 10);
    break;
  }
}

// Middleware
app.use(cors({
  origin: true, // Allow requests from any origin with credentials
  credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(cookieParser());

// Session middleware for maintaining login state
app.use(session({
  secret: process.env.SESSION_SECRET || '2300eb7c4df9f46422bd8ad47fc08aeb53e9c96fd65e99d3f327af7537bccc27',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Set up multer for file storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

// Create uploads directory if it does not exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Connect to MongoDB
connectDB().then(() => {
  console.log('Connected to MongoDB for OAuth server');
}).catch(err => {
  console.error('Failed to connect to MongoDB:', err);
});

// Helper functions
function generateRandomString(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

function generateJWT(payload, expiresIn = '1h') {
  const secret = process.env.SESSION_SECRET || '2300eb7c4df9f46422bd8ad47fc08aeb53e9c96fd65e99d3f327af7537bccc27';
  // Check if payload already has an 'exp' property to avoid conflict with expiresIn option
  const options = payload.exp ? {} : { expiresIn };
  return jwt.sign(payload, secret, options);
}

function verifyJWT(token) {
  const secret = process.env.SESSION_SECRET || '2300eb7c4df9f46422bd8ad47fc08aeb53e9c96fd65e99d3f327af7537bccc27';
  try {
    return jwt.verify(token, secret);
  } catch (error) {
    return null;
  }
}

// OIDC Discovery Endpoint
app.get('/.well-known/openid-configuration', (req, res) => {
  // Use the request's origin or forwarded host to determine the base URL
  // This ensures the issuer matches the URL used to access the endpoint
  const baseUrl = req.headers['x-forwarded-host'] ? 
    `${req.headers['x-forwarded-proto'] || req.protocol}://${req.headers['x-forwarded-host']}` : 
    `${req.protocol}://${req.get('host')}`;
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
    jwks_uri: `${baseUrl}/oauth/jwks`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['HS256', 'RS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    claims_supported: ['sub', 'iss', 'name', 'picture', 'face_verified', 'email'],
    registration_endpoint: `${baseUrl}/oauth/register`,
    end_session_endpoint: `${baseUrl}/oauth/logout`,
    revocation_endpoint: `${baseUrl}/oauth/revoke`,
    introspection_endpoint: `${baseUrl}/oauth/introspect`,
    check_session_iframe: `${baseUrl}/oauth/session-check`
  });
});

// Client Registration Endpoint (for dynamic client registration)
app.post('/oauth/register', (req, res) => {
  const { client_name, redirect_uris, grant_types, response_types, scope } = req.body;
  
  if (!client_name || !redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    return res.status(400).json({ error: 'invalid_client_metadata' });
  }
  
  const clientId = `client-${generateRandomString(8)}`;
  const clientSecret = generateRandomString();
  
  clients[clientId] = {
    clientId,
    clientSecret,
    clientName: client_name,
    redirectUris: redirect_uris,
    grants: grant_types || ['authorization_code'],
    responseTypes: response_types || ['code'],
    scopes: scope ? scope.split(' ') : ['openid', 'profile']
  };
  
  res.status(201).json({
    client_id: clientId,
    client_secret: clientSecret,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_secret_expires_at: 0, // Never expires
    redirect_uris,
    grant_types: clients[clientId].grants,
    response_types: clients[clientId].responseTypes,
    token_endpoint_auth_method: 'client_secret_basic'
  });
});

// Authorization Endpoint
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state } = req.query;
  
  // Validate request parameters
  const client = clients[client_id];
  if (!client) {
    return res.redirect(`${redirect_uri}?error=invalid_client&error_description=Invalid client identifier&state=${state || ''}`);
  }
  
  if (!client.redirectUris.includes(redirect_uri)) {
    return res.redirect(`${redirect_uri}?error=invalid_redirect_uri&error_description=Invalid redirection URI&state=${state || ''}`);
  }
  
  if (response_type !== 'code') {
    return res.redirect(`${redirect_uri}?error=unsupported_response_type&error_description=Unsupported response type&state=${state || ''}`);
  }
  
  // Store the authorization request details
  const authRequest = {
    clientId: client_id,
    redirectUri: redirect_uri,
    scope: scope || '',
    state: state || ''
  };
  
  // Render a modern login page that matches the JewelTrack design
  res.send(`
    <html>
      <head>
        <title>Face Authentication</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { 
            font-family: Arial, sans-serif; 
            margin: 0; 
            padding: 20px;
            background-color: #fffbf0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
          }
          .container { 
            width: 100%;
            max-width: 450px; 
            margin: 0 auto; 
            background-color: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
          }
          .icon-container {
            display: flex;
            justify-content: center;
            margin-bottom: 20px;
          }
          .dollar-icon {
            background-color: #ffd54f;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: #333;
          }
          h1 { 
            color: #333; 
            text-align: center;
            margin-bottom: 5px;
            font-size: 22px;
            font-weight: 600;
          }
          .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 25px;
            font-size: 14px;
          }
          .btn { 
            display: block;
            background: #666;
            color: white; 
            padding: 12px 24px; 
            text-decoration: none; 
            border-radius: 4px; 
            margin-top: 20px;
            border: none;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            text-align: center;
          }
          .btn:hover {
            background: #555;
          }
          @media (max-width: 480px) {
            .container {
              padding: 20px;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="icon-container">
            <div class="dollar-icon">$</div>
          </div>
          <h1>JewelTrack Authentication</h1>
          <p class="subtitle">Authenticate with facial recognition to continue</p>
          <a href="/face-auth?request=${Buffer.from(JSON.stringify(authRequest)).toString('base64')}" class="btn">Continue with Face Authentication</a>
        </div>
      </body>
    </html>
  `);
});

// Face Authentication Page
app.get('/face-auth', (req, res) => {
  const requestData = req.query.request;
  if (!requestData) {
    return res.status(400).send('Invalid request');
  }
  
  try {
    const authRequest = JSON.parse(Buffer.from(requestData, 'base64').toString());
    
    // Render the face authentication page with modern JewelTrack design
    res.send(`
      <html>
        <head>
          <title>Face Authentication</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body { 
              font-family: Arial, sans-serif; 
              margin: 0; 
              padding: 20px;
              background-color: #fffbf0;
              display: flex;
              justify-content: center;
              align-items: center;
              min-height: 100vh;
            }
            .container { 
              width: 100%;
              max-width: 450px; 
              margin: 0 auto; 
              background-color: white;
              padding: 30px;
              border-radius: 12px;
              box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
              text-align: center;
            }
            .icon-container {
              display: flex;
              justify-content: center;
              margin-bottom: 20px;
            }
            .dollar-icon {
              background-color: #ffd54f;
              width: 40px;
              height: 40px;
              border-radius: 50%;
              display: flex;
              align-items: center;
              justify-content: center;
              font-size: 24px;
              color: #333;
            }
            h1 { 
              color: #333; 
              text-align: center;
              margin-bottom: 5px;
              font-size: 22px;
              font-weight: 600;
            }
            .subtitle {
              text-align: center;
              color: #666;
              margin-bottom: 25px;
              font-size: 14px;
            }
            #video-container { 
              margin: 20px 0; 
              border-radius: 8px;
              overflow: hidden;
              box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            }
            #video { 
              width: 100%;
              max-width: 400px;
              border-radius: 8px;
              display: block;
              margin: 0 auto;
            }
            .btn { 
              background: #666; 
              color: white; 
              padding: 12px 24px; 
              text-decoration: none; 
              border-radius: 4px; 
              margin-top: 20px;
              border: none;
              cursor: pointer;
              font-size: 14px;
            }
            .btn:hover {
              background: #555;
            }
            .btn-register { 
              background: #34a853; 
              margin-left: 10px;
            }
            .btn-register:hover {
              background: #2d9348;
            }
            @media (max-width: 480px) {
              .container {
                padding: 20px;
              }
              .btn {
                display: block;
                width: 100%;
                margin: 10px auto;
              }
              .btn-register {
                margin-left: 0;
              }
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="icon-container">
              <div class="dollar-icon">$</div>
            </div>
            <h1>Face Authentication</h1>
            <p class="subtitle">Please look at the camera to authenticate</p>
            
            <div id="video-container">
              <video id="video" width="400" height="300" autoplay></video>
              <canvas id="canvas" width="400" height="300" style="display:none;"></canvas>
            </div>
            
            <div>
              <button id="authenticate-btn" class="btn">Authenticate</button>
              <button id="register-btn" class="btn btn-register">Register New Face</button>
            </div>
            
            <form id="auth-form" method="post" action="/face-auth/verify" style="display:none;">
              <input type="hidden" name="request" value="${requestData}">
              <input type="hidden" name="faceImage" id="face-image">
              <input type="hidden" name="action" id="action-type">
            </form>
            
            <script src="https://cdn.jsdelivr.net/npm/face-api.js@0.22.2/dist/face-api.min.js"></script>
            <style>
              /* Loading spinner styles */
              .loading-container {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                background-color: rgba(255, 255, 255, 0.9);
                z-index: 10;
                border-radius: 12px;
              }
              
              .spinner {
                width: 50px;
                height: 50px;
                border: 5px solid #f3f3f3;
                border-top: 5px solid #ffd54f;
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin-bottom: 15px;
              }
              
              @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
              }
              
              .loading-text {
                font-size: 16px;
                color: #333;
                text-align: center;
                margin-top: 10px;
              }
              
              .loading-progress {
                font-size: 14px;
                color: #666;
                margin-top: 5px;
              }
            </style>
            
            <script>
              const video = document.getElementById('video');
              const canvas = document.getElementById('canvas');
              const authForm = document.getElementById('auth-form');
              const faceImageInput = document.getElementById('face-image');
              const actionTypeInput = document.getElementById('action-type');
              const authenticateBtn = document.getElementById('authenticate-btn');
              const registerBtn = document.getElementById('register-btn');
              
              let modelsLoaded = false;
              
              // Create loading overlay
              const loadingContainer = document.createElement('div');
              loadingContainer.className = 'loading-container';
              
              const spinner = document.createElement('div');
              spinner.className = 'spinner';
              
              const loadingText = document.createElement('div');
              loadingText.className = 'loading-text';
              loadingText.textContent = 'Loading face detection models...';
              
              const loadingProgress = document.createElement('div');
              loadingProgress.className = 'loading-progress';
              loadingProgress.textContent = 'Please wait a moment';
              
              loadingContainer.appendChild(spinner);
              loadingContainer.appendChild(loadingText);
              loadingContainer.appendChild(loadingProgress);
              
              // Add loading overlay to container
              document.querySelector('.container').appendChild(loadingContainer);
              
              // Disable buttons while loading
              authenticateBtn.disabled = true;
              registerBtn.disabled = true;
              
              // Load face-api.js models
              async function loadModels() {
                const MODEL_URL = '/models';
                try {
                  loadingProgress.textContent = 'Loading face detector...';
                  await faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL);
                  
                  loadingProgress.textContent = 'Loading facial landmarks...';
                  await faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL);
                  
                  loadingProgress.textContent = 'Loading face recognition...';
                  await faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL);
                  
                  modelsLoaded = true;
                  
                  // Remove loading overlay
                  loadingContainer.style.display = 'none';
                  
                  // Enable buttons
                  authenticateBtn.disabled = false;
                  registerBtn.disabled = false;
                } catch (error) {
                  console.error('Error loading models:', error);
                  loadingText.textContent = 'Error loading face detection models';
                  loadingProgress.textContent = 'Please refresh the page and try again';
                  loadingProgress.style.color = '#e53935';
                }
              }
              
              // Start video stream
              async function startVideo() {
                try {
                  const stream = await navigator.mediaDevices.getUserMedia({ video: {} });
                  video.srcObject = stream;
                } catch (err) {
                  console.error('Error accessing camera:', err);
                  loadingText.textContent = 'Camera access error';
                  loadingProgress.textContent = 'Please ensure camera access is allowed and refresh the page';
                  loadingProgress.style.color = '#e53935';
                }
              }
              
              // Capture face image
              function captureFace(action) {
                if (!modelsLoaded) {
                  // Show loading container again if models aren't loaded
                  loadingContainer.style.display = 'flex';
                  return;
                }
                
                const context = canvas.getContext('2d');
                context.drawImage(video, 0, 0, canvas.width, canvas.height);
                
                // Get the image data as base64
                const imageData = canvas.toDataURL('image/jpeg');
                faceImageInput.value = imageData.split(',')[1]; // Remove the data URL prefix
                actionTypeInput.value = action;
                
                // For registration, redirect to registration form first
                if (action === 'register') {
                  // Store the face image in session storage temporarily
                  sessionStorage.setItem('faceImage', imageData.split(',')[1]);
                  // Redirect to registration form
                  window.location.href = '/register?request=${requestData}';
                } else {
                  // For authentication, submit the form directly
                  authForm.submit();
                }
              }
              
              // Initialize
              loadModels();
              startVideo();
              
              // Event listeners
              authenticateBtn.addEventListener('click', () => captureFace('authenticate'));
              registerBtn.addEventListener('click', () => captureFace('register'));
            </script>
          </div>
        </body>
      </html>
    `);
  } catch (error) {
    console.error('Error parsing request data:', error);
    res.status(400).send('Invalid request format');
  }
});

// User Registration Form
app.get('/register', (req, res) => {
  const requestData = req.query.request;
  if (!requestData) {
    return res.status(400).send('Invalid request');
  }
  
  // Render the registration form HTML inline
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Create Account</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          margin: 0;
          padding: 20px;
          background-color: #fffbf0;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
        }

        .container {
          width: 100%;
          max-width: 450px;
          margin: 0 auto;
          background-color: white;
          padding: 30px;
          border-radius: 12px;
          box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
        }

        .icon-container {
          display: flex;
          justify-content: center;
          margin-bottom: 20px;
        }

        .dollar-icon {
          background-color: #ffd54f;
          width: 40px;
          height: 40px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 24px;
          color: #333;
        }

        h1 {
          color: #333;
          text-align: center;
          margin-bottom: 5px;
          font-size: 22px;
          font-weight: 600;
        }

        .subtitle {
          text-align: center;
          color: #666;
          margin-bottom: 25px;
          font-size: 14px;
        }

        .form-row {
          display: flex;
          gap: 15px;
          margin-bottom: 15px;
        }

        .form-group {
          margin-bottom: 15px;
          flex: 1;
        }

        label {
          display: block;
          margin-bottom: 6px;
          font-weight: 500;
          color: #333;
          font-size: 14px;
        }

        input[type="text"],
        input[type="email"],
        input[type="tel"] {
          width: 100%;
          padding: 10px;
          border: 1px solid #ddd;
          border-radius: 4px;
          font-size: 14px;
          box-sizing: border-box;
        }

        input[type="text"]:focus,
        input[type="email"]:focus,
        input[type="tel"]:focus {
          outline: none;
          border-color: #4285f4;
        }

        .btn {
          display: block;
          width: 100%;
          background: #666;
          color: white;
          padding: 12px 24px;
          text-decoration: none;
          border-radius: 4px;
          margin-top: 20px;
          border: none;
          cursor: pointer;
          font-size: 14px;
          font-weight: 500;
          text-align: center;
        }

        .btn:hover {
          background: #555;
        }

        @media (max-width: 480px) {
          .form-row {
            flex-direction: column;
            gap: 0;
          }

          .container {
            padding: 20px;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="icon-container">
          <div class="dollar-icon">$</div>
        </div>

        <h1>Create Account</h1>
        <p class="subtitle">Enter your details to get started</p>

        <form id="registration-form" method="post" action="/register-user">
          <input type="hidden" name="request" id="request-data" value="${requestData}">

          <div class="form-row">
            <div class="form-group">
              <label for="firstName">First Name</label>
              <input type="text" id="firstName" name="firstName" placeholder="John" required>
            </div>

            <div class="form-group">
              <label for="lastName">Last Name</label>
              <input type="text" id="lastName" name="lastName" placeholder="Doe" required>
            </div>
          </div>

          <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" placeholder="john@example.com" required>
          </div>

          <div class="form-group">
            <label for="username">Username (optional)</label>
            <input type="text" id="username" name="username">
          </div>

          <div class="form-group">
            <label for="phone">Phone Number (optional)</label>
            <input type="tel" id="phone" name="phone" placeholder="+1 (555) 123-4567">
          </div>

          <button type="submit" class="btn">Create account</button>
        </form>
      </div>

      <script>
        document.addEventListener('DOMContentLoaded', function () {
          // Form validation
          document.getElementById('registration-form').addEventListener('submit', function (e) {
            const firstName = document.getElementById('firstName').value.trim();
            const lastName = document.getElementById('lastName').value.trim();
            const email = document.getElementById('email').value.trim();

            if (!firstName || !lastName || !email) {
              e.preventDefault();
              alert('Please fill in all required fields.');
            }
          });
        });
      </script>
    </body>
    </html>
  `);
});

// Handle Registration Form Submission
app.post('/register-user', bodyParser.urlencoded({ extended: true }), async (req, res) => {
  const { request, firstName, lastName, username, email, phone } = req.body;
  
  if (!request || !firstName || !lastName || !email) {
    return res.status(400).send('Missing required parameters');
  }
  
  try {
    // Store user data in session for later use during face verification
    req.session.userData = {
      firstName,
      lastName,
      username: username || null,
      email,
      phone: phone || null,
      emailVerified: true,
      phoneVerified: phone ? true : false
    };
    
    // Redirect to face capture page with a flag indicating this is coming from registration
    res.send(`
      <html>
        <head>
          <title>Face Capture</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body { 
              font-family: Arial, sans-serif; 
              margin: 0; 
              padding: 20px;
              background-color: #fffbf0;
              display: flex;
              justify-content: center;
              align-items: center;
              min-height: 100vh;
            }
            .container { 
              width: 100%;
              max-width: 450px; 
              margin: 0 auto; 
              background-color: white;
              padding: 30px;
              border-radius: 12px;
              box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
              text-align: center;
            }
            .icon-container {
              display: flex;
              justify-content: center;
              margin-bottom: 20px;
            }
            .dollar-icon {
              background-color: #ffd54f;
              width: 40px;
              height: 40px;
              border-radius: 50%;
              display: flex;
              align-items: center;
              justify-content: center;
              font-size: 24px;
              color: #333;
            }
            h1 { 
              color: #333; 
              text-align: center;
              margin-bottom: 5px;
              font-size: 22px;
              font-weight: 600;
            }
            .subtitle {
              text-align: center;
              color: #666;
              margin-bottom: 25px;
              font-size: 14px;
            }
            #video-container { 
              margin: 20px 0; 
              border-radius: 8px;
              overflow: hidden;
              box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            }
            #video { 
              width: 100%;
              max-width: 400px;
              border-radius: 8px;
              display: block;
              margin: 0 auto;
            }
            .btn { 
              display: block; 
              background: #666; 
              color: white; 
              padding: 12px 24px; 
              text-decoration: none; 
              border-radius: 4px; 
              margin-top: 20px;
              border: none;
              cursor: pointer;
              font-size: 14px;
              font-weight: 500;
            }
            .btn:hover {
              background: #555;
            }
            @media (max-width: 480px) {
              .container {
                padding: 20px;
              }
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="icon-container">
              <div class="dollar-icon">$</div>
            </div>
            <h1>Face Registration</h1>
            <p class="subtitle">Please look at the camera to register your face</p>
            
            <div id="video-container">
              <video id="video" width="400" height="300" autoplay></video>
              <canvas id="canvas" width="400" height="300" style="display:none;"></canvas>
            </div>
            
            <button id="capture-btn" class="btn">Capture Face</button>
            
            <form id="auth-form" method="post" action="/face-auth/verify" style="display:none;">
              <input type="hidden" name="request" value="${request}">
              <input type="hidden" name="faceImage" id="face-image">
              <input type="hidden" name="action" value="register">
            </form>
            
            <script src="https://cdn.jsdelivr.net/npm/face-api.js@0.22.2/dist/face-api.min.js"></script>
            <script>
              const video = document.getElementById('video');
              const canvas = document.getElementById('canvas');
              const authForm = document.getElementById('auth-form');
              const faceImageInput = document.getElementById('face-image');
              const captureBtn = document.getElementById('capture-btn');
              
              let modelsLoaded = false;
              
              // Load face-api.js models
              async function loadModels() {
                const MODEL_URL = '/models';
                await faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL);
                await faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL);
                await faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL);
                modelsLoaded = true;
              }
              
              // Start video stream
              async function startVideo() {
                try {
                  const stream = await navigator.mediaDevices.getUserMedia({ video: {} });
                  video.srcObject = stream;
                } catch (err) {
                  console.error('Error accessing camera:', err);
                  alert('Could not access the camera. Please ensure camera access is allowed.');
                }
              }
              
              // Capture face image
              function captureFace() {
                if (!modelsLoaded) {
                  alert('Face detection models are still loading. Please wait.');
                  return;
                }
                
                const context = canvas.getContext('2d');
                context.drawImage(video, 0, 0, canvas.width, canvas.height);
                
                // Get the image data as base64
                const imageData = canvas.toDataURL('image/jpeg');
                faceImageInput.value = imageData.split(',')[1]; // Remove the data URL prefix
                
                // Submit the form
                authForm.submit();
              }
              
              // Initialize
              loadModels();
              startVideo();
              
              // Event listeners
              captureBtn.addEventListener('click', captureFace);
            </script>
          </div>
        </body>
      </html>
    `);
  } catch (error) {
    console.error('Error processing registration:', error);
    res.status(500).send('Registration failed: ' + error.message);
  }
});

// Face Authentication Verification Endpoint
app.post('/face-auth/verify', bodyParser.urlencoded({ extended: true }), async (req, res) => {
  const { request, faceImage, action } = req.body;
  
  if (!request || !faceImage) {
    return res.status(400).send('Missing required parameters');
  }
  
  try {
    const authRequest = JSON.parse(Buffer.from(request, 'base64').toString());
    const { clientId, redirectUri, state } = authRequest;
    
    // Convert base64 to buffer for saving
    const imageBuffer = Buffer.from(faceImage, 'base64');
    const fileName = `${Date.now()}.jpg`;
    const filePath = path.join(uploadDir, fileName);
    
    // Save the image locally
    fs.writeFileSync(filePath, imageBuffer);
    
    // Extract face descriptor from the image
    const faceDescriptor = await faceRecognition.extractFaceDescriptor(imageBuffer);
    
    if (!faceDescriptor) {
      // Instead of just sending a text response, serve the error page with JewelTrack design
      return res.status(400).send(`
    <html>
      <head>
        <title>Face Authentication Error</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { 
            font-family: Arial, sans-serif; 
            margin: 0; 
            padding: 20px;
            background-color: #fffbf0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
          }
          .face-auth-error-container {
            width: 100%;
            max-width: 450px; 
            margin: 0 auto; 
            background-color: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            text-align: center;
          }
          .icon-container {
            display: flex;
            justify-content: center;
            margin-bottom: 20px;
          }
          .dollar-icon {
            background-color: #ffd54f;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: #333;
          }
          h2 {
            color: #333;
            margin-bottom: 15px;
            font-size: 22px;
            font-weight: 600;
          }
          .subtitle {
            color: #666;
            margin-bottom: 25px;
            font-size: 14px;
          }
          .face-auth-error-tips {
            padding-left: 20px;
            color: #666;
            text-align: left;
            margin: 20px 0;
          }
          .face-auth-error-tips li {
            margin-bottom: 8px;
          }
          .face-auth-retry-button {
            display: block;
            width: 100%;
            padding: 12px;
            background: #666;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 25px;
            font-size: 14px;
            font-weight: 500;
          }
          .face-auth-retry-button:hover {
            background: #555;
          }
          @media (max-width: 480px) {
            .face-auth-error-container { padding: 20px; }
          }
        </style>
      </head>
      <body>
        <div class="face-auth-error-container">
          <div class="icon-container">
            <div class="dollar-icon">$</div>
          </div>
          <h2>Face Verification Failed</h2>
          <p class="subtitle">We couldn't verify your identity. Please ensure:</p>
          
          <ul class="face-auth-error-tips">
            <li>Your face is clearly visible and well-lit</li>
            <li>You're not wearing sunglasses or face coverings</li>
            <li>You're facing the camera directly</li>
            <li>You're at an appropriate distance from the camera</li>
          </ul>
          
          <button class="face-auth-retry-button" onclick="window.history.back()">Try Again</button>
        </div>
      </body>
    </html>
  `);
    }
    
    let userId;
    let isNewUser = false;
    let user = null;
    
    if (action === 'register') {
      // For registration, generate a new user ID and create a new face profile
      userId = generateRandomString(16);
      isNewUser = true;
      
      // Upload image to Cloudinary
      let cloudinaryResult;
      try {
        cloudinaryResult = await cloudinary.uploadImageToCloudinary(imageBuffer, userId);
        console.log('Image uploaded to Cloudinary:', cloudinaryResult.secure_url);
        
        // Delete the temporary file after successful Cloudinary upload
        if (cloudinaryResult && fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
          console.log('Temporary file deleted after Cloudinary upload:', filePath);
        }
      } catch (cloudinaryError) {
        console.error('Cloudinary upload failed:', cloudinaryError);
        // Continue with local file if Cloudinary fails
      }
      
      // Create a new face profile with the descriptor
      const faceProfile = new FaceProfile({
        userId: userId,
        faceImagePath: filePath,
        faceDescriptor: Array.from(faceDescriptor), // Convert Float32Array to regular array for MongoDB
        registeredAt: new Date()
      });
      
      // Save the face profile to MongoDB
      await faceProfile.save();
      
      // Get user data from session if available (from registration form)
      let userData = req.session.userData || {};
      
      // Create a new user with information from the registration form or generate defaults
      user = new User({
        id: userId,
        name: userData.firstName && userData.lastName ? 
              `${userData.firstName} ${userData.lastName}` : 
              `User ${userId.substring(0, 6)}`,
        firstName: userData.firstName || 'User',
        lastName: userData.lastName || userId.substring(0, 6),
        username: userData.username || null,
        email: userData.email || `user-${userId.substring(0, 6)}@example.com`,
        emailVerified: userData.emailVerified !== undefined ? userData.emailVerified : true,
        phoneNumber: userData.phone || null,
        phoneNumberVerified: userData.phoneVerified !== undefined ? userData.phoneVerified : false,
        faceVerified: true,
        profilePicture: cloudinaryResult ? cloudinaryResult.secure_url : `/uploads/${path.basename(filePath)}`,
        registeredAt: new Date(),
        updatedAt: new Date(),
        faceProfileId: userId
      });
      
      // Clear the session user data after using it
      delete req.session.userData;
      
      // Save the user to MongoDB
      await user.save();
      
      console.log('New user registered with face authentication:', userId);
    } else {
      // For authentication, find a matching face in the database
      const faceProfiles = await FaceProfile.find({});
      
      if (faceProfiles.length === 0) {
        // Instead of just returning an error, redirect to the registration page
        // with the original request data preserved
        return res.send(`
          <html>
            <head>
              <title>No Registered Faces</title>
              <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .container { max-width: 600px; margin: 0 auto; text-align: center; }
                h1 { color: #333; }
                .message { background-color: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin: 20px 0; }
                .btn { 
                  display: inline-block; 
                  background: #34a853; 
                  color: white; 
                  padding: 10px 20px; 
                  text-decoration: none; 
                  border-radius: 5px; 
                  margin-top: 20px;
                  border: none;
                  cursor: pointer;
                }
              </style>
            </head>
            <body>
              <div class="container">
                <h1>Face Authentication</h1>
                <div class="message">
                  <p>No registered faces found. Please register first to continue.</p>
                </div>
                <a href="/register?request=${request}" class="btn">Register Now</a>
              </div>
            </body>
          </html>
        `);
      }
      
      // Find the best matching face
      const matchingProfile = faceRecognition.findMatchingFace(faceDescriptor, faceProfiles);
      
      if (!matchingProfile) {
        return res.redirect(`${redirectUri}?error=access_denied&error_description=Face+authentication+failed&state=${state || ''}`);
      }
      
      userId = matchingProfile.userId;
      
      // Get the user associated with this face profile
      user = await User.findOne({ id: userId });
      
      if (!user) {
        return res.status(401).send('User not found for the authenticated face.');
      }
      
      console.log('User authenticated with face recognition:', userId);
      
      // Delete the temporary file after authentication
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log('Temporary file deleted after authentication:', filePath);
      }
    }
    
    // Store authentication session
    req.session.userId = userId;
    req.session.authenticated = true;
    
    // Generate authorization code
    const code = generateRandomString();
    const authCode = new AuthCode({
      code: code,
      clientId: clientId,
      userId: userId,
      redirectUri: redirectUri,
      scope: authRequest.scope,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
      nonce: authRequest.nonce
    });
    
    // Save the authorization code to MongoDB
    await authCode.save();
    
    // Redirect back to client with authorization code
    const redirectUrl = new URL(redirectUri);
    redirectUrl.searchParams.append('code', code);
    if (state) {
      redirectUrl.searchParams.append('state', state);
    }
    
    res.redirect(redirectUrl.toString());
  } catch (error) {
    console.error('Error processing face authentication:', error);
    // Clean up temporary file in case of error
    if (filePath && fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      console.log('Temporary file deleted after error:', filePath);
    }
    res.status(500).send('Authentication failed: ' + error.message);
  }
});

// Token Endpoint
app.post('/oauth/token', async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;
  
  // Validate client credentials
  const client = clients[client_id];
  if (!client || client.clientSecret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
  }
  
  // Handle refresh token grant
  if (grant_type === 'refresh_token') {
    const { refresh_token } = req.body;
    const refreshTokenDoc = await Token.findOne({
      token: refresh_token,
      isRefreshToken: true
    });

    if (!refreshTokenDoc || refreshTokenDoc.expiresAt < new Date()) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    await Token.deleteOne({ token: refresh_token });

    // Generate new tokens
    const accessToken = generateRandomString();
    const refreshToken = generateRandomString();
    const accessTokenExpires = new Date(Date.now() + 3600 * 1000);
    const refreshTokenExpires = new Date(Date.now() + 30 * 24 * 3600 * 1000);

    // Store new tokens
    await Promise.all([
      new Token({
        token: accessToken,
        userId: refreshTokenDoc.userId,
        clientId: client_id,
        scope: refreshTokenDoc.scope,
        expiresAt: accessTokenExpires
      }).save(),
      new Token({
        token: refreshToken,
        userId: refreshTokenDoc.userId,
        clientId: client_id,
        scope: refreshTokenDoc.scope,
        isRefreshToken: true,
        expiresAt: refreshTokenExpires
      }).save()
    ]);

    // Return new tokens
    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: refreshToken,
      refresh_expires_in: 604800,
      id_token: generateJWT({
        sub: refreshTokenDoc.userId,
        iss: req.headers['x-forwarded-host'] ? 
          `${req.headers['x-forwarded-proto'] || req.protocol}://${req.headers['x-forwarded-host']}` : 
          `${req.protocol}://${req.get('host')}`,
        exp: Math.floor(accessTokenExpires.getTime() / 1000)
      })
    });
  }

  // Validate authorization code grant type
  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
  
  try {
    // Validate authorization code from MongoDB
    const authCodeData = await AuthCode.findOne({ code: code });
    if (!authCodeData || 
        authCodeData.clientId !== client_id || 
        authCodeData.redirectUri !== redirect_uri || 
        authCodeData.expiresAt < new Date()) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    
    // Delete the used authorization code
    await AuthCode.deleteOne({ code: code });
    
    // Get user data from MongoDB
    let user = await User.findOne({ id: authCodeData.userId });
    
    if (!user) {
      // If user not found, create a default user (shouldn't happen in normal flow)
      user = {
        id: authCodeData.userId,
        name: `User ${authCodeData.userId.substring(0, 6)}`,
        email: `user-${authCodeData.userId.substring(0, 6)}@example.com`,
        faceVerified: true
      };
    }
    
    // Generate access token and ID token
    const accessToken = generateRandomString();
    const refreshToken = generateRandomString();
    
    // Get face profile for the user from MongoDB
    const faceProfile = await FaceProfile.findOne({ userId: user.id });
    
    // Log face profile data for debugging
    console.log('User ID:', user.id);
    console.log('Face Profile found:', !!faceProfile);
    
    // Get profile picture URL (prefer Cloudinary URL if available)
    const profilePictureUrl = user.profilePicture || 
      (faceProfile ? `/uploads/${path.basename(faceProfile.faceImagePath)}` : null);
    
    const idToken = generateJWT({
      // Required OIDC claims
      iss: req.headers['x-forwarded-host'] ? 
        `${req.headers['x-forwarded-proto'] || req.protocol}://${req.headers['x-forwarded-host']}` : 
        `${req.protocol}://${req.get('host')}`,
      sub: user.id,
      aud: client_id,
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      auth_time: Math.floor(Date.now() / 1000),
      nonce: authCodeData.nonce,
      
      // Additional claims mapped to Clerk's attribute mapping
      name: user.name,
      given_name: user.firstName || 'User',
      family_name: user.lastName || user.id.substring(0, 6),
      preferred_username: user.username || null,
      email: user.email,
      email_verified: user.emailVerified !== undefined ? user.emailVerified : true,
      phone_number: user.phoneNumber || null,
      phone_number_verified: user.phoneNumberVerified !== undefined ? user.phoneNumberVerified : false,
      face_verified: user.faceVerified !== undefined ? user.faceVerified : true,
      picture: profilePictureUrl,
      updated_at: Math.floor(user.updatedAt?.getTime() / 1000) || Math.floor(Date.now() / 1000)
    });
    
    // Store access token in MongoDB
    const accessTokenDoc = new Token({
      token: accessToken,
      userId: user.id,
      clientId: client_id,
      scope: authCodeData.scope,
      expiresAt: new Date(Date.now() + 3600 * 1000) // 1 hour
    });
    await accessTokenDoc.save();
    
    // Store refresh token in MongoDB
    const refreshTokenDoc = new Token({
      token: refreshToken,
      userId: user.id,
      clientId: client_id,
      scope: authCodeData.scope,
      isRefreshToken: true,
      expiresAt: new Date(Date.now() + 30 * 24 * 3600 * 1000) // 30 days
    });
    await refreshTokenDoc.save();
    
    // Return tokens
    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: refreshToken,
      refresh_expires_in: 604800,
      id_token: idToken
    });
  } catch (error) {
    console.error('Error processing token request:', error);
    res.status(500).json({ error: 'server_error' });
  }
});

// UserInfo Endpoint
app.get('/oauth/userinfo', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  
  const accessToken = authHeader.substring(7);
  
  try {
    // Get token data from MongoDB
    const tokenData = await Token.findOne({ token: accessToken, isRefreshToken: false });
    
    if (!tokenData || tokenData.expiresAt < new Date()) {
      return res.status(401).json({ error: 'invalid_token' });
    }
    
    // Get user data from MongoDB
    let user = await User.findOne({ id: tokenData.userId });
    
    if (!user) {
      // If user not found, create a default user (shouldn't happen in normal flow)
      user = {
        id: tokenData.userId,
        name: `User ${tokenData.userId.substring(0, 6)}`,
        firstName: 'User',
        lastName: tokenData.userId.substring(0, 6),
        email: `user-${tokenData.userId.substring(0, 6)}@example.com`,
        emailVerified: true,
        faceVerified: true
      };
    }
    
    // Get face profile for the user
    const faceProfile = await FaceProfile.findOne({ userId: user.id });
    
    // Get profile picture URL (prefer user's profilePicture if available)
    const profilePictureUrl = user.profilePicture || 
      (faceProfile ? `/uploads/${path.basename(faceProfile.faceImagePath)}` : null);
    
    // Return user info with Clerk-compatible attributes
    res.json({
      sub: user.id,
      name: user.name,
      given_name: user.firstName || 'User',
      family_name: user.lastName || user.id.substring(0, 6),
      preferred_username: user.username || null,
      email: user.email,
      email_verified: user.emailVerified !== undefined ? user.emailVerified : true,
      phone_number: user.phoneNumber || null,
      phone_number_verified: user.phoneNumberVerified !== undefined ? user.phoneNumberVerified : false,
      face_verified: user.faceVerified !== undefined ? user.faceVerified : true,
      picture: profilePictureUrl,
      updated_at: Math.floor(user.updatedAt?.getTime() / 1000) || Math.floor(Date.now() / 1000)
    });
  } catch (error) {
    console.error('Error processing userinfo request:', error);
    res.status(500).json({ error: 'server_error' });
  }
});


// Logout Endpoint
app.get('/oauth/logout', (req, res) => {
  // Clear session
  req.session.destroy();
  
  // Get post_logout_redirect_uri from query params
  const redirectUri = req.query.post_logout_redirect_uri || 'http://localhost:3000';
  
  res.redirect(redirectUri);
});

// Existing image upload endpoint from the original server
app.post('/upload', upload.single('image'), (req, res) => {
  if (!req.file) {
    console.error('No file uploaded.');
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  console.log('Received file:', req.file);

  // Use the request's origin or forwarded host to determine the base URL
  const baseUrl = req.headers['x-forwarded-host'] ? 
    `${req.headers['x-forwarded-proto'] || req.protocol}://${req.headers['x-forwarded-host']}` : 
    `${req.protocol}://${req.get('host')}`;
    
  const fileUrl = `${baseUrl}/${req.file.filename}`;
  res.status(200).json({ fileName: req.file.filename, filePath: fileUrl });
});

// JWKS Endpoint for OIDC compliance
app.get('/oauth/jwks', (req, res) => {
  // In a production environment, you would use a proper JWKS library like jwks-rsa
  // For this demo, we'll return a simple JWKS structure
  const jwks = {
    keys: [
      {
        kty: 'oct',
        kid: '1',
        use: 'sig',
        alg: 'HS256',
        // Note: In a real implementation, you would NOT expose your secret key
        // This is just for demonstration purposes
        k: Buffer.from(process.env.SESSION_SECRET || '2300eb7c4df9f46422bd8ad47fc08aeb53e9c96fd65e99d3f327af7537bccc27')
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, '')
      }
    ]
  };
  
  res.json(jwks);
});

// Token revocation endpoint
app.post('/oauth/revoke', async (req, res) => {
  const { token } = req.body;
  await Token.deleteOne({ token });
  res.status(200).end();
});

// Session management endpoints
app.get('/oauth/session', (req, res) => {
  res.json({
    client_id: req.session.clientId,
    user: req.session.userId,
    authenticated: !!req.session.authenticated,
    expires: req.session.cookie.expires
  });
});

app.post('/oauth/backchannel-logout', async (req, res) => {
  const { logout_token } = req.body;
  const decoded = verifyJWT(logout_token);
  
  if (decoded?.sub) {
    await Token.deleteMany({ userId: decoded.sub });
    await AuthCode.deleteMany({ userId: decoded.sub });
  }
  res.status(204).end();
});

// Introspection endpoint (required for some OIDC clients)
app.post('/oauth/introspect', async (req, res) => {
  const { token, token_type_hint } = req.body;
  
  if (!token) {
    return res.status(400).json({ error: 'invalid_request' });
  }
  
  try {
    // Get token data from MongoDB
    const tokenData = await Token.findOne({ token: token });
    
    if (!tokenData || tokenData.expiresAt < new Date()) {
      return res.json({ active: false });
    }
    
    // Get user data from MongoDB
    const user = await User.findOne({ id: tokenData.userId });
    
    res.json({
      active: true,
      client_id: tokenData.clientId,
      username: user ? user.name : undefined,
      scope: tokenData.scope,
      sub: tokenData.userId,
      exp: Math.floor(tokenData.expiresAt.getTime() / 1000),
      iat: Math.floor((tokenData.expiresAt.getTime() - 3600 * 1000) / 1000),
      token_type: tokenData.isRefreshToken ? 'refresh_token' : 'access_token'
    });
  } catch (error) {
    console.error('Error introspecting token:', error);
    res.status(500).json({ error: 'server_error' });
  }
});

// Endpoint to serve face-api.js models
app.use('/models', express.static(path.join(__dirname, 'public', 'models')));

// Initialize face-api.js models
faceRecognition.loadModels().catch(err => {
  console.error('Failed to load face-api.js models:', err);
});

// Connect to MongoDB and start the server
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`OAuth 2.0 Server with Face Authentication is running on http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to connect to MongoDB:', err);
});