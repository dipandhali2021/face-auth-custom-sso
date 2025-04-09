// Face recognition utilities for server-side face authentication
const faceapi = require('face-api.js');
const canvas = require('canvas');
const fs = require('fs');
const path = require('path');

// Configure face-api.js to use canvas
const { Canvas, Image, ImageData } = canvas;
faceapi.env.monkeyPatch({ Canvas, Image, ImageData });

// Path to face-api.js models
const MODELS_PATH = path.join(__dirname, '..', 'public', 'models');

// Initialize face-api.js models
let modelsLoaded = false;

/**
 * Load face-api.js models
 */
async function loadModels() {
  if (modelsLoaded) return;
  
  try {
    // Load models from the models directory
    await faceapi.nets.tinyFaceDetector.loadFromDisk(MODELS_PATH);
    await faceapi.nets.faceLandmark68Net.loadFromDisk(MODELS_PATH);
    await faceapi.nets.faceRecognitionNet.loadFromDisk(MODELS_PATH);
    
    modelsLoaded = true;
    console.log('Face-api.js models loaded successfully');
  } catch (error) {
    console.error('Error loading face-api.js models:', error);
    throw error;
  }
}

/**
 * Extract face descriptor from an image
 * @param {Buffer} imageBuffer - Image buffer
 * @returns {Promise<Float32Array|null>} - Face descriptor or null if no face detected
 */
async function extractFaceDescriptor(imageBuffer) {
  if (!modelsLoaded) await loadModels();
  
  try {
    // Load image
    const img = await canvas.loadImage(imageBuffer);
    
    // Detect face and get descriptor
    const detections = await faceapi
      .detectSingleFace(img, new faceapi.TinyFaceDetectorOptions())
      .withFaceLandmarks()
      .withFaceDescriptor();
    
    if (!detections) {
      console.log('No face detected in the image');
      return null;
    }
    
    return detections.descriptor;
  } catch (error) {
    console.error('Error extracting face descriptor:', error);
    return null;
  }
}

/**
 * Compare face descriptors to determine if they match
 * @param {Float32Array} descriptor1 - First face descriptor
 * @param {Float32Array} descriptor2 - Second face descriptor
 * @param {number} threshold - Matching threshold (lower is more strict)
 * @returns {boolean} - True if faces match, false otherwise
 */
function compareFaceDescriptors(descriptor1, descriptor2, threshold = 0.6) {
  if (!descriptor1 || !descriptor2) return false;
  
  // Calculate Euclidean distance between descriptors
  const distance = faceapi.euclideanDistance(descriptor1, descriptor2);
  console.log('Face matching distance:', distance);
  
  // Return true if distance is below threshold
  return distance < threshold;
}

/**
 * Find matching face in a list of face profiles
 * @param {Float32Array} targetDescriptor - Target face descriptor
 * @param {Array} faceProfiles - Array of face profiles with descriptors
 * @param {number} threshold - Matching threshold
 * @returns {Object|null} - Matching face profile or null if no match
 */
function findMatchingFace(targetDescriptor, faceProfiles, threshold = 0.6) {
  if (!targetDescriptor || !faceProfiles || faceProfiles.length === 0) {
    return null;
  }
  
  let bestMatch = null;
  let bestDistance = Infinity;
  
  // Find the closest matching face
  for (const profile of faceProfiles) {
    if (!profile.faceDescriptor) continue;
    
    const distance = faceapi.euclideanDistance(
      targetDescriptor, 
      new Float32Array(profile.faceDescriptor)
    );
    
    if (distance < threshold && distance < bestDistance) {
      bestDistance = distance;
      bestMatch = profile;
    }
  }
  
  return bestMatch;
}

module.exports = {
  loadModels,
  extractFaceDescriptor,
  compareFaceDescriptors,
  findMatchingFace
};