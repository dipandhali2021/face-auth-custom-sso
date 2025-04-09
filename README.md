# Face Authentication OAuth Server

A complete OAuth 2.0 server implementation with facial recognition authentication, built with Node.js, Express, and MongoDB.

## Overview

This project implements a custom OAuth 2.0 Authorization Server with facial recognition as the primary authentication method. It allows applications to authenticate users through their face, providing a passwordless and secure authentication experience.

## Features

- **OAuth 2.0 Authorization Code Flow**: Standard OAuth implementation with support for OpenID Connect
- **Face Authentication**: Biometric authentication using face recognition
- **User Registration**: Complete user registration flow with face enrollment
- **MongoDB Integration**: Persistent storage for user profiles and face data
- **Cloudinary Integration**: Cloud storage for profile images
- **JWT Tokens**: Secure token generation and validation
- **OIDC Compliant**: Follows OpenID Connect standards for identity verification

## Tech Stack

### Backend
- **Node.js**: JavaScript runtime environment
- **Express**: Web application framework
- **MongoDB**: NoSQL database for storing user data and face profiles
- **Mongoose**: MongoDB object modeling for Node.js
- **face-api.js**: JavaScript API for face detection and recognition
- **JWT**: JSON Web Tokens for secure authentication
- **Multer**: Middleware for handling file uploads
- **Cloudinary**: Cloud service for image storage and management

### Frontend
- **React**: JavaScript library for building user interfaces
- **React Router**: Navigation for React applications
- **face-api.js (client-side)**: Face detection in the browser
- **HTML5 Canvas**: For capturing and processing face images

## Architecture

### OAuth Server Components

1. **Authorization Endpoint** (`/oauth/authorize`)
   - Initiates the OAuth flow
   - Redirects to face authentication

2. **Token Endpoint** (`/oauth/token`)
   - Exchanges authorization codes for tokens
   - Issues access tokens, ID tokens, and refresh tokens

3. **User Info Endpoint** (`/oauth/userinfo`)
   - Returns authenticated user information
   - Includes face verification status

4. **Face Authentication Flow**
   - Face capture using browser camera
   - Server-side face recognition and matching
   - User registration with face enrollment

5. **Database Models**
   - User: Stores user profile information
   - FaceProfile: Stores face descriptors and image paths
   - Token: Manages OAuth tokens
   - AuthCode: Handles authorization codes

## Setup Instructions

### Prerequisites

- Node.js (v14 or higher)
- MongoDB (local instance or MongoDB Atlas)
- Cloudinary account for image storage

### Installation

1. Clone the repository
   ```
   git clone <repository-url>
   cd react-face-detection-main
   ```

2. Install dependencies
   ```
   npm install
   ```

3. Configure environment variables
   Create a `.env` file in the root directory with the following variables:
   ```
   # Server Configuration
   PORT=5001
   NODE_ENV=development

   # MongoDB Configuration
   MONGODB_URI=mongodb://localhost:27017/face-auth

   # Session and OAuth Configuration
   SESSION_SECRET=your_session_secret
   OAUTH_CLIENT_ID=face-auth-client
   OAUTH_CLIENT_SECRET=your_client_secret

   # Cloudinary Configuration
   NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME=your_cloud_name
   CLOUDINARY_API_KEY=your_api_key
   CLOUDINARY_API_SECRET=your_api_secret
   ```

4. Start the OAuth server
   ```
   node oauth-server.js
   ```

5. Start the React frontend
   ```
   npm start
   ```

## Usage

### OAuth Client Integration

To integrate with the OAuth server from a client application:

1. Register your client application with the OAuth server
2. Redirect users to the authorization endpoint:
   ```
   http://localhost:5001/oauth/authorize?client_id=face-auth-client&redirect_uri=http://localhost:3000/oauth/callback&response_type=code&scope=openid profile&state=random_state
   ```

3. Exchange the authorization code for tokens:
   ```javascript
   const response = await fetch('http://localhost:5001/oauth/token', {
     method: 'POST',
     headers: {
       'Content-Type': 'application/json'
     },
     body: JSON.stringify({
       grant_type: 'authorization_code',
       code: 'received_code',
       redirect_uri: 'http://localhost:3000/oauth/callback',
       client_id: 'face-auth-client',
       client_secret: 'your_client_secret'
     })
   });
   ```

4. Access user information with the token:
   ```javascript
   const userInfo = await fetch('http://localhost:5001/oauth/userinfo', {
     headers: {
       'Authorization': `Bearer ${access_token}`
     }
   });
   ```

### Face Authentication Flow

1. User is redirected to the face authentication page
2. New users can register by clicking "Register New Face"
3. Existing users can authenticate by looking at the camera
4. Upon successful authentication, the user is redirected back to the client application with an authorization code

## OpenID Connect Integration

The server supports OpenID Connect discovery at the standard endpoint:
```
/.well-known/openid-configuration
```

This provides all necessary endpoints and supported features for OIDC clients.

## Security Considerations

- Face descriptors are stored securely in the database
- JWT tokens are signed with a secure secret
- HTTPS is recommended for production deployments
- Session management with secure cookies
- Face matching threshold can be adjusted for security vs. convenience

## Clerk SSO Integration

This OAuth server can be integrated with Clerk as a custom OAuth provider:

1. In your Clerk dashboard, add a new OAuth provider
2. Configure the provider with the following settings:
   - Authorization URL: `http://localhost:5001/oauth/authorize`
   - Token URL: `http://localhost:5001/oauth/token`
   - User Info URL: `http://localhost:5001/oauth/userinfo`
   - Client ID: `face-auth-client`
   - Client Secret: Your client secret
   - Scopes: `openid profile`

3. Add `https://your-clerk-domain.clerk.accounts.dev/v1/oauth_callback` to the allowed redirect URIs in your OAuth server configuration

## License

MIT
