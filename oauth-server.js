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
const { connectDB, User, FaceProfile, Token, AuthCode } = require('./utils/db');
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
app.use(express.static(path.join(__dirname, 'public')));
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
  
  // Read the HTML file and replace the placeholder with the request data
  const authorizePage = fs.readFileSync(path.join(__dirname, 'public', 'authorize.html'), 'utf8');
  const renderedPage = authorizePage.replace('{{requestData}}', Buffer.from(JSON.stringify(authRequest)).toString('base64'));
  
  res.send(renderedPage);
});

// Face Authentication Page
app.get('/face-auth', (req, res) => {
  const requestData = req.query.request;
  if (!requestData) {
    return res.status(400).send('Invalid request');
  }
  
  try {
    // Parse the request data to validate it
    JSON.parse(Buffer.from(requestData, 'base64').toString());
    
    // Serve the face authentication HTML file
    res.sendFile(path.join(__dirname, 'public', 'face-auth.html'));
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
  
  // Serve the registration form HTML file
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
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
    
    // Redirect to face capture page with the request data
    res.redirect(`/face-capture.html?request=${encodeURIComponent(request)}`);
  } catch (error) {
    console.error('Error processing registration:', error);
    res.status(500).send('Registration failed: ' + error.message);
  }
});
  

// Middleware to clean up temporary files when redirecting to error pages
app.use((req, res, next) => {
  // Store the original redirect method
  const originalRedirect = res.redirect;
  
  // Override the redirect method
  res.redirect = function(url) {
    // If there's a temporary file path in the session, try to delete it
    if (req.session && req.session.tempFilePath && fs.existsSync(req.session.tempFilePath)) {
      try {
        fs.unlinkSync(req.session.tempFilePath);
        console.log('Temporary file deleted during redirect:', req.session.tempFilePath);
        // Clear the temporary file path from session
        delete req.session.tempFilePath;
      } catch (error) {
        console.error('Error deleting temporary file during redirect:', error);
      }
    }
    
    // Call the original redirect method
    return originalRedirect.apply(this, arguments);
  };
  
  next();
});

// Face Authentication Verification Endpoint
app.post('/face-auth/verify', bodyParser.urlencoded({ extended: true }), async (req, res) => {
  const { request, faceImage, action } = req.body;
  
  if (!request || !faceImage) {
    return res.status(400).send('Missing required parameters');
  }
  
  // Define a cleanup function to ensure file deletion in all scenarios
  let filePath = null;
  const cleanupTempFile = () => {
    if (filePath && fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
        console.log('Temporary file deleted:', filePath);
      } catch (cleanupError) {
        console.error('Error deleting temporary file:', cleanupError);
      }
    }
  };

  try {
    const authRequest = JSON.parse(Buffer.from(request, 'base64').toString());
    const { clientId, redirectUri, state } = authRequest;
    
    // Convert base64 to buffer for saving
    const imageBuffer = Buffer.from(faceImage, 'base64');
    const fileName = `${Date.now()}.jpg`;
    filePath = path.join(uploadDir, fileName);
    
    // Save the image locally
    fs.writeFileSync(filePath, imageBuffer);
    
    // Store the temporary file path in session for cleanup during redirects
    req.session.tempFilePath = filePath;
    
    // Extract face descriptor from the image
    const faceDescriptor = await faceRecognition.extractFaceDescriptor(imageBuffer);
    
    if (!faceDescriptor) {
      // Delete the temporary file if no face is detected
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log('Temporary file deleted after no face detected:', filePath);
      }
      // Serve the error page for face verification failure
      return res.status(400).sendFile(path.join(__dirname, 'public', 'face-auth-error.html'));
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
        // Delete the temporary file if no registered faces exist
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
          console.log('Temporary file deleted when no registered faces exist:', filePath);
        }
        // Redirect to the no-registered-faces page with the request data
        return res.redirect(`/no-registered-faces.html?request=${encodeURIComponent(request)}`);
      }
      
      // Find the best matching face
      const matchingProfile = faceRecognition.findMatchingFace(faceDescriptor, faceProfiles);
      
      if (!matchingProfile) {
        // Delete the temporary file if no matching face is found
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
          console.log('Temporary file deleted after no face match found:', filePath);
        }
        // Redirect to the face-match-failed page with the request data instead of error redirect
        return res.redirect(`/face-match-failed.html?request=${encodeURIComponent(request)}`);
      }
      
      userId = matchingProfile.userId;
      
      // Get the user associated with this face profile
      user = await User.findOne({ id: userId });
      
      if (!user) {
        // Delete the temporary file if no user is found for the face
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
          console.log('Temporary file deleted when no user found for face:', filePath);
        }
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
    cleanupTempFile();
    res.status(500).send('Authentication failed: ' + error.message);
  } finally {
    // Ensure cleanup happens even if there's an unhandled exception
    cleanupTempFile();
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