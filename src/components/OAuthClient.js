import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import './OAuthClient.css';

const OAuthClient = () => {
  const [searchParams] = useSearchParams();
  const [authState, setAuthState] = useState({
    isAuthenticated: false,
    user: null,
    error: null,
    loading: false
  });

  // Check if we have an authorization code from the OAuth server
  useEffect(() => {
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    
    if (code) {
      exchangeCodeForToken(code, state);
    }
  }, [searchParams]);

  // Exchange authorization code for tokens
  const exchangeCodeForToken = async (code, state) => {
    setAuthState(prev => ({ ...prev, loading: true }));
    
    try {
      const response = await fetch('http://localhost:5001/oauth/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'http://localhost:3000/oauth/callback',
          client_id: 'face-auth-client',
          client_secret: '2f4faadac82f1b78aec68aea3de330303f3aa90531222f35e656943e581aa118'
        })
      });

      if (!response.ok) {
        throw new Error('Failed to exchange code for token');
      }

      const data = await response.json();
      
      // Store tokens in localStorage (in a real app, use a more secure method)
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('id_token', data.id_token);
      
      // Fetch user info with the access token
      await fetchUserInfo(data.access_token);
    } catch (error) {
      console.error('Token exchange error:', error);
      setAuthState(prev => ({
        ...prev,
        loading: false,
        error: error.message
      }));
    }
  };

  // Fetch user information from the userinfo endpoint
  const fetchUserInfo = async (accessToken) => {
    try {
      const response = await fetch('http://localhost:5001/oauth/userinfo', {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });

      if (!response.ok) {
        throw new Error('Failed to fetch user info');
      }

      const userData = await response.json();
      
      setAuthState({
        isAuthenticated: true,
        user: userData,
        loading: false,
        error: null
      });

      // In a real app, you would integrate with Clerk here
      // For example, using Clerk's signIn or signUp methods with the OAuth data
    } catch (error) {
      console.error('User info fetch error:', error);
      setAuthState(prev => ({
        ...prev,
        loading: false,
        error: error.message
      }));
    }
  };

  // Initiate OAuth flow
  const startOAuthFlow = (isRegistration = false) => {
    // Generate a random state for CSRF protection
    const state = Math.random().toString(36).substring(2, 15);
    localStorage.setItem('oauth_state', state);
    
    // Generate a nonce for OIDC
    const nonce = Math.random().toString(36).substring(2, 15);
    localStorage.setItem('oauth_nonce', nonce);
    
    // Redirect to authorization endpoint
    const authUrl = new URL('http://localhost:5001/oauth/authorize');
    authUrl.searchParams.append('client_id', 'face-auth-client');
    authUrl.searchParams.append('redirect_uri', 'http://localhost:3000/oauth/callback');
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('scope', 'openid profile email');
    authUrl.searchParams.append('state', state);
    authUrl.searchParams.append('nonce', nonce);
    
    // Add registration hint if registering
    if (isRegistration) {
      authUrl.searchParams.append('prompt', 'create');
    }
    
    window.location.href = authUrl.toString();
  };

  // Log out
  const logout = () => {
    const idToken = localStorage.getItem('id_token');
    
    // Clear local storage
    localStorage.removeItem('access_token');
    localStorage.removeItem('id_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('oauth_state');
    localStorage.removeItem('oauth_nonce');
    
    // Reset state
    setAuthState({
      isAuthenticated: false,
      user: null,
      error: null,
      loading: false
    });
    
    // Redirect to OIDC logout endpoint
    const logoutUrl = new URL('http://localhost:5001/oauth/logout');
    logoutUrl.searchParams.append('post_logout_redirect_uri', 'http://localhost:3000');
    if (idToken) {
      logoutUrl.searchParams.append('id_token_hint', idToken);
    }
    
    window.location.href = logoutUrl.toString();
  };

  return (
    <div className="oauth-client">
      <h2>Face Authentication with OAuth 2.0</h2>
      
      {authState.loading && <p>Loading...</p>}
      
      {authState.error && (
        <div className="error-message">
          <p>Error: {authState.error}</p>
          <button onClick={() => setAuthState(prev => ({ ...prev, error: null }))}>Dismiss</button>
        </div>
      )}
      
      {authState.isAuthenticated ? (
        <div className="user-profile">
          <h3>Welcome, {authState.user.name}!</h3>
          {authState.user.picture && (
            <div className="profile-image">
              <img 
                src={`http://localhost:5001${authState.user.picture}`} 
                alt="Profile" 
                style={{ width: '100px', height: '100px', borderRadius: '50%' }} 
              />
            </div>
          )}
          <p>User ID: {authState.user.sub}</p>
          <p>Email: {authState.user.email}</p>
          <p>Face Verified: {authState.user.face_verified ? 'Yes' : 'No'}</p>
          <button onClick={logout} className="logout-button">Log Out</button>
        </div>
      ) : (
        <div className="auth-actions">
          <p>Use your face to authenticate</p>
          <div className="auth-buttons">
            <button 
              onClick={() => startOAuthFlow(false)} 
              className="login-button"
            >
              Login with Face Authentication
            </button>
            <button 
              onClick={() => startOAuthFlow(true)} 
              className="register-button"
            >
              Register New Face
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default OAuthClient;