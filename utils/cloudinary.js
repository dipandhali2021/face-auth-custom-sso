// Cloudinary integration for profile picture uploads
const cloudinary = require('cloudinary').v2;
const { Readable } = require('stream');

// Configure Cloudinary with credentials
cloudinary.config({
  cloud_name: process.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

/**
 * Upload an image buffer to Cloudinary
 * @param {Buffer} imageBuffer - The image buffer to upload
 * @param {string} userId - User ID to use in the public_id
 * @returns {Promise<Object>} - Cloudinary upload result
 */
async function uploadImageToCloudinary(imageBuffer, userId) {
  try {
    // Create a readable stream from the buffer
    const stream = Readable.from(imageBuffer);
    
    // Create a promise to handle the stream upload
    return new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: 'face-auth-profiles',
          public_id: `user-${userId}`,
          overwrite: true,
          resource_type: 'image',
          transformation: [
            { width: 250, height: 250, crop: 'fill', gravity: 'face' }
          ]
        },
        (error, result) => {
          if (error) return reject(error);
          resolve(result);
        }
      );
      
      stream.pipe(uploadStream);
    });
  } catch (error) {
    console.error('Error uploading to Cloudinary:', error);
    throw error;
  }
}

/**
 * Get a Cloudinary URL for a user's profile picture
 * @param {string} userId - The user ID
 * @returns {string} - Cloudinary URL
 */
function getUserProfileImageUrl(userId) {
  return cloudinary.url(`face-auth-profiles/user-${userId}`, {
    secure: true,
    width: 250,
    height: 250,
    crop: 'fill',
    gravity: 'face'
  });
}

module.exports = {
  uploadImageToCloudinary,
  getUserProfileImageUrl
};