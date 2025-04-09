import React, { useEffect, useRef, useState } from 'react';
import * as faceapi from 'face-api.js';
import './FaceRecognition.css';

const FaceRecognition = ({ videoRef, handleVideoOnPlay, detections }) => {
  const [capturedImages, setCapturedImages] = useState([]);
  const [noFaceDetected, setNoFaceDetected] = useState(false);

  useEffect(() => {
    const startVideo = () => {
      navigator.mediaDevices
        .getUserMedia({ video: {} })
        .then((stream) => {
          videoRef.current.srcObject = stream;
        })
        .catch((err) => console.error(err));
    };

    startVideo();
  }, [videoRef]);

  useEffect(() => {
    if (videoRef.current) {
      videoRef.current.addEventListener('play', () => {
        const canvas = faceapi.createCanvasFromMedia(videoRef.current);
        const displaySize = {
          width: videoRef.current.width,
          height: videoRef.current.height,
        };
        faceapi.matchDimensions(canvas, displaySize);

        const drawDetections = () => {
          const context = canvas.getContext('2d');
          context.clearRect(0, 0, canvas.width, canvas.height);
          const resizedDetections = faceapi.resizeResults(detections, displaySize);
          faceapi.draw.drawDetections(canvas, resizedDetections);
          faceapi.draw.drawFaceLandmarks(canvas, resizedDetections);
          faceapi.draw.drawFaceExpressions(canvas, resizedDetections);
        };

        if (detections.length > 0) {
          drawDetections();
        }
      });
    }
  }, [detections, videoRef]);

  const captureImage = () => {
    const video = videoRef.current;

    if (video) {
      const canvas = document.createElement('canvas');
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;

      const context = canvas.getContext('2d');
      context.drawImage(video, 0, 0, canvas.width, canvas.height);

      // Check if faces are detected
      if (detections.length > 0) {
        setNoFaceDetected(false);
        const resizedDetections = faceapi.resizeResults(detections, {
          width: canvas.width,
          height: canvas.height,
        });
        faceapi.draw.drawDetections(canvas, resizedDetections);
        faceapi.draw.drawFaceLandmarks(canvas, resizedDetections);
        faceapi.draw.drawFaceExpressions(canvas, resizedDetections);
      } else {
        setNoFaceDetected(true);
      }

      const dataUrl = canvas.toDataURL('image/jpeg');
      setCapturedImages([...capturedImages, dataUrl]);

      const byteString = atob(dataUrl.split(',')[1]);
      const mimeString = dataUrl.split(',')[0].split(':')[1].split(';')[0];
      const ab = new ArrayBuffer(byteString.length);
      const ia = new Uint8Array(ab);
      for (let i = 0; i < byteString.length; i++) {
        ia[i] = byteString.charCodeAt(i);
      }
      const blob = new Blob([ab], { type: mimeString });

      const formData = new FormData();
      formData.append('image', blob, 'capture.jpg');

      fetch('http://localhost:5000/upload', {
        method: 'POST',
        body: formData,
      })
        .then((response) => {
          if (!response.ok) {
            throw new Error('Failed to upload image.');
          }
          return response.json();
        })
        .then((data) => {
          console.log('Image saved successfully', data);
        })
        .catch((error) => {
          console.error('Error saving image:', error);
        });
    }
  };

  return (
    <div className="face-recognition-container">
      <video
        ref={videoRef}
        autoPlay
        muted
        onPlay={handleVideoOnPlay}
        width="720"
        height="560"
        className="video-stream"
      />
      <button onClick={captureImage} className="capture-button">
        Capture Image
      </button>
      
      {noFaceDetected && (
        <div className="no-face-detected">
          <div className="no-face-icon">😕</div>
          <h3>No face detected in the image</h3>
          <p>Please try again with a clearer image or better lighting conditions.</p>
          <ul className="face-detection-tips">
            <li>Make sure your face is clearly visible</li>
            <li>Ensure good lighting on your face</li>
            <li>Position yourself directly in front of the camera</li>
            <li>Remove any face coverings or obstructions</li>
          </ul>
        </div>
      )}
      
      <div className="captured-images-container">
        {capturedImages.map((image, index) => (
          <img
            key={index}
            src={image}
            alt={`Captured ${index}`}
            className="captured-image"
          />
        ))}
      </div>
    </div>
  );
};

export default FaceRecognition;
