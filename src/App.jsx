import React, { useEffect, useRef, useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import * as faceapi from 'face-api.js';
import FaceRecognition from './components/FaceRecognition';
import OAuthClient from './components/OAuthClient';
import './App.css';

function App() {
  const videoRef = useRef(null);
  const [modelsLoaded, setModelsLoaded] = useState(false);
  const [detections, setDetections] = useState([]);
  const [activeComponent, setActiveComponent] = useState('oauth');
  const [error, setError] = useState(null);

  useEffect(() => {
    // Load face-api.js models
    const loadModels = async () => {
      const MODEL_URL = '/models';
      try {
        console.log('Loading models from:', MODEL_URL);
        await Promise.all([
          faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
          faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL),
          faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL),
          faceapi.nets.faceExpressionNet.loadFromUri(MODEL_URL)
        ]);
        setModelsLoaded(true);
        console.log('Models loaded successfully');
      } catch (error) {
        console.error('Error loading models:', error);
        setError('Failed to load face detection models. Please make sure the models are available in the public/models directory.');
      }
    };
    
    loadModels();
  }, []);

  const handleVideoOnPlay = () => {
    setInterval(async () => {
      if (videoRef.current) {
        const detections = await faceapi.detectAllFaces(
          videoRef.current,
          new faceapi.TinyFaceDetectorOptions()
        ).withFaceLandmarks().withFaceExpressions();

        setDetections(detections);
      }
    }, 100);
  };

  return (
    <Router>
      <div className="App">
        <h1>Face Authentication App</h1>
        <div className="toggle-container">
          <button
            onClick={() => setActiveComponent('oauth')}
            className={`toggle-btn ${activeComponent === 'oauth' ? 'active' : ''}`}
          >
            Face Authentication
          </button>
          <button
            onClick={() => setActiveComponent('faceRecognition')}
            className={`toggle-btn ${activeComponent === 'faceRecognition' ? 'active' : ''}`}
          >
            Face Recognition Demo
          </button>
        </div>
        <Routes>
          <Route path="/" element={
            <div>
              {error ? (
                <div className="error-message">
                  <p>{error}</p>
                </div>
              ) : modelsLoaded ? (
                <div className="app-container">
                  {activeComponent === 'faceRecognition' ? (
                    <div className="face-recognition-section">
                      <FaceRecognition
                        videoRef={videoRef}
                        handleVideoOnPlay={handleVideoOnPlay}
                        detections={detections}
                      />
                    </div>
                  ) : (
                    <div className="oauth-section">
                      <OAuthClient />
                    </div>
                  )}
                </div>
              ) : (
                <p>Loading face recognition models...</p>
              )}
            </div>
          } />
          <Route path="/oauth/callback" element={<OAuthClient />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
