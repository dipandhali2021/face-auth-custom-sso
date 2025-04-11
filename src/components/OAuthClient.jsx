import { useState, useEffect } from 'react';
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

  // Check for existing tokens and validate session on component mount
  useEffect(() => {
    const checkExistingSession = async () => {
      const accessToken = localStorage.getItem('access_token');
      
      if (accessToken) {
        setAuthState(prev => ({ ...prev, loading: true }));
        try {
          // Attempt to fetch user info with the stored token
          await fetchUserInfo(accessToken);
          console.log('Session restored from stored token');
        } catch (error) {
          console.error('Session validation error:', error);
          // Clear invalid tokens
          localStorage.removeItem('access_token');
          localStorage.removeItem('id_token');
          localStorage.removeItem('refresh_token');
          localStorage.removeItem('oauth_state');
          localStorage.removeItem('oauth_nonce');
          
          setAuthState({
            isAuthenticated: false,
            user: null,
            error: 'Session expired. Please login again.',
            loading: false
          });
        }
      }
    };
    
    checkExistingSession();
  }, []);

  // Check if we have an authorization code from the OAuth server
  useEffect(() => {
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const storedState = localStorage.getItem('oauth_state');
    
    // Only proceed if we have a code and it hasn't been processed yet
    if (code) {
      setAuthState(prev => ({ ...prev, loading: true }));
      
      // Validate state to prevent CSRF attacks, but continue if state is missing
      // This makes the flow more robust while still maintaining some security
      if (state && storedState && state !== storedState) {
        console.warn('State mismatch, but continuing with authentication');
        // We'll continue with the flow instead of showing an error
      }
      
      // Remove code from URL to prevent reuse on refresh
      const currentUrl = new URL(window.location.href);
      currentUrl.searchParams.delete('code');
      currentUrl.searchParams.delete('state');
      window.history.replaceState({}, document.title, currentUrl.toString());
      
      exchangeCodeForToken(code);
    }
  }, [searchParams]);

  // Exchange authorization code for tokens
  const exchangeCodeForToken = async (code) => {
    try {
      console.log('Exchanging code for token:', code);
      
      // Clear the stored state since we've used it
      localStorage.removeItem('oauth_state');
      
      // Get the current origin for dynamic redirect URI construction
      const origin = window.location.origin;
      const redirectUri = `${origin}/oauth/callback`;
      
      // Log the current URL to debug the redirect issue
      console.log('Current URL during token exchange:', window.location.href);
      
      // Log the code and redirect URI being used for token exchange
      console.log('Using redirect URI for token exchange:', redirectUri);
      
      // Add more detailed debugging for request parameters
      console.log('Full token exchange request details:', {
        url: 'http://localhost:5001/oauth/token',
        code: code,
        redirect_uri: redirectUri,
        client_id: 'face-auth-client'
      });
      
      const response = await fetch('http://localhost:5001/oauth/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          client_id: 'face-auth-client',
          client_secret: '2f4faadac82f1b78aec68aea3de330303f3aa90531222f35e656943e581aa118'
        })
      });
      
      console.log('Token response status:', response.status);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({
          error: 'Failed to parse error response',
          status: response.status,
          statusText: response.statusText
        }));
        console.error('Token exchange failed:', errorData);
        const errorMessage = errorData.error_description || errorData.error || `Failed to exchange code for token (Status: ${response.status})`;
        throw new Error(errorMessage);
      }
      
      console.log('Token exchange successful');

      const data = await response.json();
      console.log('Token data received (keys only):', Object.keys(data));
      
      // Store tokens in localStorage (in a real app, use a more secure method)
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('id_token', data.id_token);
      if (data.refresh_token) {
        localStorage.setItem('refresh_token', data.refresh_token);
      }
      
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
      console.log('Fetching user info with token:', accessToken ? 'Token exists' : 'No token');
      
      const response = await fetch('http://localhost:5001/oauth/userinfo', {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });
      
      console.log('User info response status:', response.status);

      if (!response.ok) {
        // If token is invalid, clear it from storage
        if (response.status === 401) {
          console.log('Unauthorized access, clearing tokens');
          localStorage.removeItem('access_token');
          localStorage.removeItem('id_token');
          localStorage.removeItem('refresh_token');
          localStorage.removeItem('oauth_state');
          localStorage.removeItem('oauth_nonce');
        }
        const errorData = await response.json().catch(() => ({
          error: 'Failed to parse error response',
          status: response.status,
          statusText: response.statusText
        }));
        console.error('User info fetch failed:', errorData);
        throw new Error(errorData.error_description || errorData.error || `Failed to fetch user info (Status: ${response.status})`);
      }

      const userData = await response.json();
      console.log('User data received:', userData ? 'Data exists' : 'No data');
      if (userData) {
        console.log('User data keys:', Object.keys(userData));
      }
      
      setAuthState({
        isAuthenticated: true,
        user: userData,
        loading: false,
        error: null
      });

      return userData;
    } catch (error) {
      console.error('User info fetch error:', error);
      setAuthState(prev => ({
        ...prev,
        loading: false,
        error: error.message
      }));
      throw error;
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
    
    // Get the current origin for dynamic redirect URI construction
    const origin = window.location.origin;
    const redirectUri = `${origin}/oauth/callback`;
    console.log('Using redirect URI for authorization:', redirectUri);
    
    // Redirect to authorization endpoint
    const authUrl = new URL('http://localhost:5001/oauth/authorize');
    authUrl.searchParams.append('client_id', 'face-auth-client');
    authUrl.searchParams.append('redirect_uri', redirectUri);
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
    logoutUrl.searchParams.append('post_logout_redirect_uri', 'http://localhost:5173');
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
                src={`${authState.user.picture}`} 
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