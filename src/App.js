// src/App.js
import React, { useEffect, useRef, useState, useCallback } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import * as faceapi from 'face-api.js';
import FaceRecognition from './components/FaceRecognition';
import OAuthClient from './components/oauthclient';
import './App.css';

function App() {
  const videoRef = useRef(null);
  const [modelsLoaded, setModelsLoaded] = useState(false);
  const [detections, setDetections] = useState([]);
  const [activeComponent, setActiveComponent] = useState('oauth');

  useEffect(() => {
    // Load face-api.js models
    const loadModels = async () => {
      const MODEL_URL = process.env.PUBLIC_URL + '/models';
      await faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL);
      await faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL);
      await faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL);
      await faceapi.nets.faceExpressionNet.loadFromUri(MODEL_URL);
      setModelsLoaded(true);
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
              {modelsLoaded ? (
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
 