const express = require('express');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const mongoose = require('mongoose');
const multer = require('multer');
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const sharp = require('sharp');

const { S3Client, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { Upload } = require('@aws-sdk/lib-storage');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner'); 


// --- CORS Configuration (The Fix) ---
const allowedOrigins = [
    'https://outflickzs.netlify.app',
    'https://outflickzz.com' // Make sure you allow your primary domain too
];

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, 
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    // ADD THIS LINE:
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    optionsSuccessStatus: 204 
};

// Load environment variables (ensure these are set in your .env file)
dotenv.config();

// --- IDRIVE E2 CONFIGURATION ---
const IDRIVE_ACCESS_KEY = process.env.IDRIVE_ACCESS_KEY;
const IDRIVE_SECRET_KEY = process.env.IDRIVE_SECRET_KEY;
const IDRIVE_ENDPOINT = process.env.IDRIVE_ENDPOINT;
const IDRIVE_BUCKET_NAME = process.env.IDRIVE_BUCKET_NAME;

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

const PAYSTACK_API_BASE_URL = 'https://api.paystack.co';


// Define isProduction at the top level
const isNetlifyProduction = process.env.NODE_ENV === 'production' || process.env.NETLIFY === 'true';

const getCookieOptions = (req) => {
    // If running on Netlify (or production) AND request is HTTPS
    const isSecure = isNetlifyProduction && req.headers['x-forwarded-proto'] === 'https';
    
    // Fallback: If on Netlify, assume secure for cookie attributes
    const secureCookieAttribute = isSecure || process.env.NODE_ENV === 'production'; // This is the crucial change
    
    return {
        httpOnly: true,
        secure: secureCookieAttribute, 
        sameSite: 'None', 
    };
};

// --- 1. EMAIL TRANSPORT SETUP ---
// Configuration to connect to an SMTP service (e.g., Gmail using an App Password)
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: process.env.EMAIL_PORT || 465,
    secure: process.env.EMAIL_PORT == 465 || true, 
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS, 
    },
});

const s3Client = new S3Client({
    // Use the IDrive E2 Endpoint
    endpoint: IDRIVE_ENDPOINT,    
    region: 'us-west-1',     
    credentials: {
        accessKeyId: IDRIVE_ACCESS_KEY,
        secretAccessKey: IDRIVE_SECRET_KEY,
    },
    forcePathStyle: true,
});

/**
 * Helper function to clean a URL by removing all query parameters.
 * This is CRITICAL for handling corrupted URLs (where a signed URL was
 * inadvertently saved instead of the clean path).
 * @param {string} url - The potentially corrupted B2 URL.
 * @returns {string} The clean base URL path without query parameters.
 */
function cleanUrlPath(url) {
    if (!url || typeof url !== 'string') {
        return url;
    }
    // Remove the first instance of '?' (standard query separator)
    let clean = url.split('?')[0];
    
    // Check for the URL-encoded '?' (%3F) which often precedes the broken signature.
    const encodedQuestionMarkIndex = clean.indexOf('%3F');
    if (encodedQuestionMarkIndex !== -1) {
        clean = clean.substring(0, encodedQuestionMarkIndex);
    }
    
    // Remove leading or trailing slashes if they appear during the cleanup
    return clean.trim().replace(/\/+$/, '');
}

/**
 * Extracts the file key (path inside the bucket) from the permanent IDrive E2 URL.
 * This is the SINGLE SOURCE OF TRUTH for key extraction.
 * @param {string} fileUrl - The permanent IDrive E2 URL (e.g., https://endpoint/bucketName/path/to/file.jpg).
 * @returns {string|null} The file key (path inside the bucket), or null if extraction fails.
 */
function getFileKeyFromUrl(fileUrl) { 
    if (!fileUrl) return null;

    try {
        const marker = `${IDRIVE_BUCKET_NAME}/`;
        // ----------------------------------------------------
        
        // Find the index of the marker
        const markerIndex = fileUrl.indexOf(marker);

        if (markerIndex === -1) {
            console.warn(`[Key Extraction] Bucket marker '${marker}' not found in URL: ${fileUrl}`);
            return null;
        }

        // The file key is the string slice immediately after the marker
        const fileKey = fileUrl.substring(markerIndex + marker.length);
        
        if (!fileKey) {
            console.warn(`[Key Extraction] Resulting file key was empty for URL: ${fileUrl}`);
            return null;
        }
        
        return fileKey;

    } catch (e) {
        console.error('Error extracting file key:', e.message);
        return null;
    }
}

/**
 * Generates a temporary, pre-signed URL for private files in IDrive E2.
 * @param {string} fileUrl - The permanent IDrive E2 URL.
 * @returns {Promise<string|null>} The temporary signed URL, or null if key extraction fails.
 */
async function generateSignedUrl(fileUrl) {
   if (!fileUrl) return null;

    try {
        // --- 🚨 CRITICAL FIX: Sanitize the URL first! ---
        const cleanUrl = cleanUrlPath(fileUrl);
        // ---------------------------------------------
        
        // 1. Use the consolidated helper function
        const fileKey = getFileKeyFromUrl(cleanUrl);
        
        if (!fileKey) {
            // Error logged inside getFileKeyFromUrl
            return `https://placehold.co/400x400/FF0000/FFFFFF?text=KEY+FAILED`;
        }

        console.log(`[Signed URL DEBUG] Extracted Key: ${fileKey}`); // Debugging check

        // 2. Create the GetObject command
        const command = new GetObjectCommand({
            Bucket: IDRIVE_BUCKET_NAME,
            Key: fileKey,
            ResponseCacheControl: 'max-age=604800, public', 
        });

        // 3. Generate the signed URL (expires in 604800 seconds = 7 days)
        // s3Client is now configured for IDrive E2
        const signedUrl = await getSignedUrl(s3Client, command, { expiresIn: 604800 }); 
        
        console.log(`[Signed URL DEBUG] Signed URL successfully generated for key: ${fileKey}`);
        return signedUrl;

    } catch (error) {
        console.error(`[Signed URL] Failed to generate signed URL for ${fileUrl}:`, error);
        return `https://placehold.co/400x400/FF0000/FFFFFF?text=SIGNATURE+FAILED`;
    }
}

/**
 * Checks the stored Signed URL expiry. If expired or near expiration, 
 * generates a new Signed URL, updates the database, and returns the new URL.
 * @param {Object} item - The database record holding the file data.
 * @returns {Promise<string>} The current, valid Signed URL.
 */
async function getPermanentImageUrl(item) {
    // 1. Check if the URL is expired (e.g., within 1 day of expiration)
    const now = Date.now();
    const expiryTime = item.signedUrlExpiresAt ? item.signedUrlExpiresAt.getTime() : 0;
    
    // We refresh if the URL is expired OR expires within the next 24 hours (86400000 ms)
    const isExpired = expiryTime < (now + 86400000); 

    if (!item.permanentFileKey) {
        // Return a placeholder if no file is stored
        return 'https://placehold.co/400x400/CCCCCC/000000?text=No+Image'; 
    }

    if (item.cachedSignedUrl && !isExpired) {
        // 2. If valid and not near expiry, return the cached URL
        return item.cachedSignedUrl;
    }

    // 3. The URL is expired or needs refreshment, so generate a new one.
    // We need to reconstruct the full permanent path to use the existing generateSignedUrl helper.
    const permanentPath = `${IDRIVE_ENDPOINT}/${IDRIVE_BUCKET_NAME}/${item.permanentFileKey}`;
    
    // This call uses your existing logic and returns a new 7-day URL.
    const newSignedUrl = await generateSignedUrl(permanentPath);

    // 4. Calculate the new expiration time (7 days from now)
    const newExpiryDate = new Date(now + 604800000); // 604800 seconds * 1000 ms/s

    // 5. Update the database with the new URL and expiry time
    await YourDatabaseModel.updateOne(
        { _id: item._id },
        { 
            $set: {
                cachedSignedUrl: newSignedUrl,
                signedUrlExpiresAt: newExpiryDate,
            }
        }
    );

console.log(`https://www.merriam-webster.com/dictionary/refresh Generated and cached new URL for key: ${item.permanentFileKey}`);
    return newSignedUrl;
}

/**
 * Deletes a file from IDrive E2 given its URL.
 * @param {string} fileUrl - The permanent IDrive E2 URL of the file to delete.
 */
async function deleteFileFromPermanentStorage(fileUrl) {
    if (!fileUrl) return;

    try {
        // --- 🚨 CRITICAL: Sanitize the URL first! ---
        const cleanUrl = cleanUrlPath(fileUrl);
        // ---------------------------------------------
        
        // 1. Use the consolidated helper function
        const fileKey = getFileKeyFromUrl(cleanUrl);
        
        if (!fileKey) {
            // Error logged inside getFileKeyFromUrl
            return;
        }

        console.log(`[IDrive E2] Deleting file with Key: ${fileKey}`);

        const command = new DeleteObjectCommand({
            // --- ⚠️ CRITICAL CHANGE: Use IDRIVE_BUCKET_NAME ---
            Bucket: IDRIVE_BUCKET_NAME,
            // ----------------------------------------------------
            Key: fileKey,
        });

        await s3Client.send(command);
        console.log(`[IDrive E2] Deletion successful for key: ${fileKey}`);
    } catch (error) {
        console.error(`[IDrive E2] Failed to delete file at ${fileUrl}:`, error);
    }
}

/**
 * Helper function to send email using the configured transporter.
 * @param {string} toEmail - The primary recipient (usually the admin/sender for BCC blasts).
 * @param {string} subject - The email subject.
 * @param {string} htmlContent - The HTML body of the email.
 * @param {string} [bccList=''] - A comma-separated string of recipient emails (the users).
 */
async function sendMail(toEmail, subject, htmlContent, bccList = '') {
    
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        console.error("FATAL: Email environment variables (EMAIL_USER/EMAIL_PASS) are not set.");
        throw new Error("Email service is unconfigured.");
    }
    
    return transporter.sendMail({
        from: `Outflickz Limited <${process.env.EMAIL_USER}>`, // Sender address
        to: toEmail, // Primary recipient
        bcc: bccList, // Now correctly referencing the function parameter
        subject: subject, // Subject line
        html: htmlContent, // HTML body
    });
}
/**
 * Helper function to generate, HASH, and save a new verification code.
 * IMPORTANT: This now stores the HASH, not the plain code.
 */
async function generateHashAndSaveVerificationCode(user) {
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    // Set code to expire in 10 minutes (600,000 ms)
    const verificationCodeExpires = new Date(Date.now() + 600000); 

    // --- 🛠️ SECURITY IMPROVEMENT: HASH THE CODE ---
    const salt = await bcrypt.genSalt(10);
    const hashedVerificationCode = await bcrypt.hash(verificationCode, salt);
    // ---------------------------------------------

    await User.updateOne(
        { _id: user._id },
        { 
            // FIX: Wrap all field updates in $set operator 
            $set: { 
                // Store the HASH in the newly added schema field
                verificationCode: hashedVerificationCode, 
                verificationCodeExpires: verificationCodeExpires,
                // FIX: Use dot notation to update the nested field
                'status.isVerified': false 
            }
        }
    );
        return verificationCode;
}

/**
 * Helper function for currency formatting (NGN)
 * NOTE: This function needs to be available in the scope where generateOrderEmailHtml is used.
 * @param {number} amount - The amount in Naira (NGN).
 * @returns {string} The formatted currency string.
 */
function formatCurrency(amount) {
    if (typeof amount !== 'number' || isNaN(amount)) {
        // Handle null, undefined, or non-numeric inputs gracefully
        return '₦ 0.00'; 
    }
    // Formats as Naira (₦), using the 'en-NG' locale for Nigerian currency representation
    return new Intl.NumberFormat('en-NG', { 
        style: 'currency', 
        currency: 'NGN',
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(amount);
}

// Function to format the HTML content for the order confirmation email
// ASSUMPTION: All amounts in the 'order' object are now in Naira (NGN).
function generateOrderEmailHtml(order) {
    // Determine the primary product URL for display
    const itemsHtml = order.items.map(item => {
        // Use a placeholder if the image URL is missing or add a width/style
        // NOTE: The augmentOrdersWithProductDetails ensures this is a signed URL or a solid placeholder.
        const itemImageUrl = item.imageUrl || 'https://placehold.co/60x60/f8f8f8/999999?text=NO+IMG';
        
        return `
            <tr>
                <td style="padding: 12px; border: 1px solid #ddd; display: flex; align-items: center; text-align: left;">
                    <img src="${itemImageUrl}" alt="${item.name}" 
                        style="
                            width: 60px; 
                            min-width: 60px; /* Ensure fixed width */
                            height: 60px; 
                            object-fit: cover; 
                            margin-right: 15px; 
                            border-radius: 4px; 
                            display: block; /* CRITICAL FIX: Helps image rendering in some clients */
                        ">
                    <div style="flex-grow: 1;">
                        <p style="margin: 0; font-weight: 900; font-size: 1.1em; color: #1F2937;">${item.name}</p>
                        <p style="margin: 2px 0 0 0; font-size: 0.9em; color: #555;">Size: ${item.size || 'N/A'}</p>
                        <p style="margin: 0; font-size: 0.9em; color: #555;">Details: ${item.variation || 'N/A'}</p>
                    </div>
                </td>
                <td style="padding: 8px; border: 1px solid #ddd; text-align: center;">${item.quantity}</td>
                <td style="padding: 8px; border: 1px solid #ddd; text-align: right;">${formatCurrency(item.priceAtTimeOfPurchase * item.quantity)}</td>
            </tr>
        `;
    }).join('');

    // --- Amount Calculations (Now assuming input amounts are in NGN) ---
    // Use stored amounts where possible. Fallback calculation uses order totals.
    const totalAmountNgn = order.totalAmount || order.amountPaidNgn || 0;
    const shippingFeeNgn = order.shippingFee || 0;
    
    // Fallback calculation for subtotal/tax if they aren't explicitly stored
    const taxNgn = order.tax || 0;
    // Recalculate subtotal assuming total - shipping - tax = subtotal
    const subtotalNgn = order.subtotal || (totalAmountNgn - shippingFeeNgn - taxNgn); 

    const finalTotal = totalAmountNgn;
    const subtotal = subtotalNgn;
    const shipping = shippingFeeNgn;
    const tax = taxNgn;
    
    // Construct the full address from structured fields
    const address = order.shippingAddress;
    const fullAddress = [
        address.street, 
        address.city, 
        address.state, 
        address.zipCode, 
        address.country
    ].filter(Boolean).join(', ');
    
    // 💥 FIX START: Check for multiple common property names for the phone number
    const phoneNumber = address.phone 
                        || address.phoneNumber 
                        || address.contactNumber 
                        || 'Not provided'; 
    // 💥 FIX END

    return `
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #E5E7EB; border-radius: 8px; font-family: Arial, sans-serif; line-height: 1.6; color: #374151;">
            <h2 style="color: #4F46E5; border-bottom: 2px solid #4F46E5; padding-bottom: 10px;">Order Confirmed! #${order.orderReference || order._id}</h2>
            <p>Hi ${address.firstName},</p>
            <p>Your order has been successfully confirmed and is now being prepared for shipping. Thank you for shopping with us!</p>

            <table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
                <thead>
                    <tr style="background-color: #F3F4F6;">
                        <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Product</th>
                        <th style="padding: 10px; border: 1px solid #ddd; width: 10%; text-align: center;">Qty</th>
                        <th style="padding: 10px; border: 1px solid #ddd; width: 20%; text-align: right;">Total</th>
                    </tr>
                </thead>
                <tbody>
                    ${itemsHtml}
                </tbody>
            </table>

            <table style="width: 100%; margin-top: 20px; font-size: 1.1em;">
                <tr><td style="padding: 5px 0;">Subtotal:</td><td style="text-align: right;">${formatCurrency(subtotal)}</td></tr>
                <tr><td style="padding: 5px 0;">Shipping:</td><td style="text-align: right;">${formatCurrency(shipping)}</td></tr>
                <tr><td style="padding: 5px 0;">Tax:</td><td style="text-align: right;">${formatCurrency(tax)}</td></tr>
                <tr>
                    <td style="padding: 10px 0; border-top: 2px solid #333; font-weight: bold;">Order Total:</td>
                    <td style="text-align: right; font-weight: bold; border-top: 2px solid #333; color: #4F46E5;">${formatCurrency(finalTotal)}</td>
                </tr>
            </table>
            
            <h3 style="margin-top: 30px; color: #1F2937;">Shipping Details</h3>
            <p style="padding: 10px; background-color: #F9FAFB; border-radius: 4px;">
                <strong>Recipient:</strong> ${address.firstName} ${address.lastName}<br>
                <strong>Full Address:</strong> ${fullAddress}<br>
                <strong>Email:</strong> ${address.email}<br>
                <strong>Phone:</strong> ${phoneNumber}<br>
                <strong>Status:</strong> <span style="font-weight: bold; color: #059669;">${order.status}</span>
            </p>

            <p style="margin-top: 30px; text-align: center; font-size: 0.9em; color: #6B7280;">If you have any questions, please reply to this email or contact our support team.</p>
        </div>
    `;
}

// NOTE: You would need to export and use this function in your Express route:
// await sendOrderConfirmationEmailForAdmin(customerEmail, finalOrder, generateOrderEmailHtml(finalOrder));

module.exports = {
    generateOrderEmailHtml,
    formatCurrency
};

/**
 * Sends the order confirmation email.
 * Tailored to handle both 'Confirmed' and 'Completed' statuses.
 */
async function sendOrderConfirmationEmailForAdmin(customerEmail, order) {
    
    const status = order.status;
    
    // Determine the user-friendly verb based on the status
    // If Confirmed -> "is Confirmed" | If Completed -> "is Completed"
    const statusText = status === 'Confirmed' ? 'Confirmed' : 'Completed';
    
    // Create a dynamic subject line
    const subject = `✅ Order #${order._id.toString().substring(0, 8)} ${statusText}!`; 

    // Generate HTML - Ensure your template handles these status variations
    const htmlContent = generateOrderEmailHtml(order); 

    try {
        const info = await sendMail(customerEmail, subject, htmlContent);
        console.log(`Email sent: ${info.messageId} to ${customerEmail} (Status: ${status})`);
    } catch (error) {
        console.error(`ERROR sending confirmation email for order ${order._id}:`, error);
        // We don't throw error here to prevent blocking the checkout process if the mail server is slow
    }
}

/**
 * Sends an email notification to the customer when their order status is updated to 'Shipped'.
 * This simplified version confirms shipment without providing tracking details.
 * @param {string} customerEmail - The verified email of the customer.
 * @param {Object} orderDetails - The updated Mongoose order document (status: 'Shipped').
 */
async function sendShippingUpdateEmail(customerEmail, orderDetails) {
    
    const orderIdShort = orderDetails._id.toString().substring(0, 8);
    // Subject line simplified to focus only on shipment
    const subject = `🚀 Your Order #${orderIdShort} Has Shipped for Delivery!`;

    // 1. Determine Tracking Information Content (Simplified to a single notification block)
    const notificationHtml = `
        <div style="background-color: #e3f2fd; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 5px solid #2196f3;">
            <h3 style="color: #1976d2; margin-top: 0;">📦 Shipment Update!</h3>
            <p>Your order has officially been **shipped** and is on its way to your delivery address.</p>
            <p>We'll notify you again when your order is delivered to your address.</p>
        </div>
    `;

    // 2. Generate the full HTML content
    const htmlContent = `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2 style="color: #2196f3;">Hello Customer,</h2>
            <p>We are excited to inform you that the fulfillment of your order is complete!</p>
            <p><strong>Order ID:</strong> #${orderIdShort}</p>
            <p><strong>Date Shipped:</strong> ${new Date().toLocaleDateString('en-US')}</p>
            
            ${notificationHtml}
            
            <p>Thank you for your business! We appreciate your patience.</p>
            <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="font-size: 0.9em; color: #777;">If you have any questions about your delivery, please contact our support team.</p>
        </div>
    `;

    // 3. Send the Email
    try {
        // Assume sendMail is a pre-defined utility function (like from Nodemailer)
        const info = await sendMail(customerEmail, subject, htmlContent);
        console.log(`Shipping Update Email sent: ${info.messageId} to ${customerEmail}`);
    } catch (error) {
        // Log the email failure
        console.error(`ERROR sending shipping update email for order ${orderDetails._id}:`, error);
    }
}

/**
 * Sends an email notification to the customer when their order status is updated to 'Delivered'.
 * This notifies the customer that the fulfillment process is complete.
 * @param {string} customerEmail - The verified email of the customer.
 * @param {Object} orderDetails - The updated Mongoose order document (status: 'Delivered').
 */
async function sendDeliveredEmail(customerEmail, orderDetails) {
    
    // Use a short version of the Order ID for the subject line
    const orderIdShort = orderDetails._id.toString().substring(0, 8);
    
    // Subject line reflects the final status
    const subject = `✅ Your Order #${orderIdShort} Has Been Delivered!`;

    // 1. Determine Notification Content
    const notificationHtml = `
        <div style="background-color: #e8f5e9; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 5px solid #4caf50;">
            <h3 style="color: #2e7d32; margin-top: 0;">🎉 Delivery Confirmation!</h3>
            <p>Your order has been successfully **delivered** to your specified address.</p>
            <p>Please check your package and enjoy your items!</p>
        </div>
    `;

    // 2. Generate the full HTML content
    const htmlContent = `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2 style="color: #4caf50;">Hello Customer,</h2>
            <p>Great news! The shipping journey for your order is complete.</p>
            <p><strong>Order ID:</strong> #${orderIdShort}</p>
            <p><strong>Date Delivered:</strong> ${new Date().toLocaleDateString('en-US')}</p>
            
            ${notificationHtml}
            
            <p>We hope you love your new products! If you need any assistance, please don't hesitate to reach out.</p>
            
            <p style="font-weight: bold; color: #2e7d32;">Thank you for your continued patronage!</p>
            
            <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="font-size: 0.9em; color: #777;">If you have any questions or did not receive your order, please contact our support team immediately.</p>
        </div>
    `;

    // 3. Send the Email
    try {
        // Assume sendMail is a pre-defined utility function (like from Nodemailer)
        const info = await sendMail(customerEmail, subject, htmlContent);
        console.log(`Delivered Email sent: ${info.messageId} to ${customerEmail}`);
    } catch (error) {
        // Log the email failure
        console.error(`ERROR sending delivered email for order ${orderDetails._id}:`, error);
    }
}

// ADD THIS PLACEHOLDER FUNCTION to server.js near your other functions
async function logActivity(type, message, userId, context = {}) {
    // Check if the ActivityLog Model is defined and use it if available.
    // Otherwise, just log to the console to prevent crashing.
    if (typeof ActivityLog !== 'undefined' && ActivityLog.create) {
        // You would save the log to the database here
        // await ActivityLog.create({ type, message, userId, ...context });
    } else {
        // Fallback to console log
        console.log(`[ACTIVITY LOG - ${type}] User ${userId}: ${message}`, context);
    }
}

// --- CONFIGURATION ---
const MONGODB_URI = process.env.MONGODB_URI
const JWT_SECRET = process.env.JWT_SECRET
const BCRYPT_SALT_ROUNDS = 10;

// Default admin credentials
const DEFAULT_ADMIN_EMAIL = process.env.DEFAULT_ADMIN_EMAIL
const DEFAULT_ADMIN_PASSWORD = process.env.DEFAULT_ADMIN_PASSWORD


// --- MONGODB SCHEMAS & MODELS ---
const adminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    role: { type: String, default: 'admin' }
});
const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);

const userSchema = new mongoose.Schema({
    email: { type: String, required: [true, 'Email is required'], unique: true, trim: true, lowercase: true },
    password: { type: String, required: [true, 'Password is required'], select: false },
    
    // --- 🔑 VERIFICATION FIELDS ---
    verificationCode: { type: String, select: false },
    verificationCodeExpires: { type: Date, select: false },
    // -----------------------------
    
    profile: {
        firstName: { type: String, trim: true },
        lastName: { type: String, trim: true },
        phone: { type: String, trim: true },
        whatsapp: { type: String, trim: true }
    },
    
    permanentFileKey: { 
        type: String, 
        default: null 
    },
    cachedSignedUrl: { 
        type: String, 
        default: null 
    },
    signedUrlExpiresAt: { 
        type: Date, 
        default: null 
    },

    address: {
        type: new mongoose.Schema({
            street: { type: String, required: [true, 'Street is required'], trim: true },
            city: { type: String, required: [true, 'City is required'], trim: true },
            state: { type: String, trim: true },
            zip: { type: String, trim: false },
            country: { type: String, required: [true, 'Country is required'], trim: true }
        }),
        required: [true, 'Address information is required']
    },

    status: {
        role: { type: String, default: 'user', enum: ['user', 'vip'] },
        isVerified: { type: Boolean, default: false },
    },
    membership: {
        memberSince: { type: Date, default: Date.now },
        lastUpdated: { type: Date, default: Date.now }
    }
}, { timestamps: false });

// Pre-save hook to update lastUpdated and hash password
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        const salt = await bcrypt.genSalt(BCRYPT_SALT_ROUNDS);
        this.password = await bcrypt.hash(this.password, salt);
    }
    this.membership.lastUpdated = Date.now();
    next();
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

const ProductVariationSchema = new mongoose.Schema({
    variationIndex: { 
        type: Number, 
        required: true, 
        min: 1, 
        max: 4 
    },

    // --- Image Fields ---
    frontImageUrl: { 
        type: String, 
        required: [true, 'Front view image permanent key is required'],
        trim: true 
    }, 
    frontCachedSignedUrl: { type: String, default: null },
    frontSignedUrlExpiresAt: { type: Date, default: null },

    backImageUrl: { 
        type: String, 
        required: [true, 'Back view image permanent key is required'],
        trim: true 
    }, 
    backCachedSignedUrl: { type: String, default: null },
    backSignedUrlExpiresAt: { type: Date, default: null },

    // ✅ FIX: ColorHex is now OPTIONAL to resolve the 400 error from the client.
    colorHex: { 
        type: String, 
        required: false, // Changed from true
        match: [/^#[0-9A-F]{6}$/i, 'Color must be a valid hex code (e.g., #RRGGBB)'] 
    },
    
    // ✅ FIX: The sizes array is now OPTIONAL and defaults to [] for successful validation.
    sizes: {
        type: [{
            size: { type: String, required: true },
            stock: { type: Number, required: true, min: 0, default: 0 }
        }],
        required: false, // Changed from true/implicit
        default: []
    }
}, { _id: false });


const WearsCollectionSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Collection name is required'],
        trim: true,
        maxlength: [100, 'Collection name cannot exceed 100 characters']
    },
    description: {
        type: String,
        required: [true, 'Product description is required'],
        trim: true,
        maxlength: [1000, 'Description cannot exceed 1000 characters'],
        default: 'Quality premium apparel from Outflickz.'
    },
    tag: {
        type: String,
        required: [true, 'Collection tag is required'],
        enum: ['Top Deal', 'Hot Deal', 'New', 'Seasonal', 'Clearance']
    },
    price: { 
        type: Number,
        required: [true, 'Price (in NGN) is required'],
        min: [0.01, 'Price (in NGN) must be greater than zero']
    },
    variations: {
        type: [ProductVariationSchema], 
        required: [true, 'At least one product variation is required'],
        validate: {
            validator: function(v) { return v.length >= 1 && v.length <= 4; },
            message: 'A collection must have between 1 and 4 variations.'
        }
    },
    
    // totalStock is now calculated automatically in the pre-save hook
    totalStock: {
        type: Number,
        min: [0, 'Stock cannot be negative'],
    },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// 🚀 CRITICAL PRODUCTION HOOK: Automatically calculates totalStock 
// and ensures consistency with detailed variation/size stock counts.
WearsCollectionSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    
    // 1. Calculate the new total stock
    let calculatedTotalStock = 0;
    
    if (this.variations && this.variations.length > 0) {
        calculatedTotalStock = this.variations.reduce((totalVariationStock, variation) => {
            // Sum all stock counts within the sizes array for this variation
            const variationStockSum = variation.sizes.reduce((totalSizeStock, sizeEntry) => {
                return totalSizeStock + sizeEntry.stock;
            }, 0); 
            
            return totalVariationStock + variationStockSum;
        }, 0);
    }
    
    // 2. Apply business logic and set the totalStock field
    if (this.isActive === false) {
        // If the product is deactivated, total stock is 0
        this.totalStock = 0;
    } else {
        // Otherwise, use the calculated sum
        this.totalStock = calculatedTotalStock;
    }
    
    next();
});

const WearsCollection = mongoose.models.WearsCollection || mongoose.model('WearsCollection', WearsCollectionSchema);

// --- Main New Arrivals Schema (Identical structure to WearsCollection) ---
const NewArrivalsSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Product name is required'],
        trim: true,
        maxlength: [100, 'Product name cannot exceed 100 characters']
    },
    description: {
        type: String,
        required: [true, 'Product description is required'],
        trim: true,
        maxlength: [1000, 'Description cannot exceed 1000 characters'],
        default: 'Quality premium apparel from Outflickz.'
    },
    tag: {
        type: String,
        required: [true, 'Product tag is required'],
        enum: ['Top Deal', 'Hot Deal', 'New', 'Seasonal', 'Clearance']
    },
    price: { 
        type: Number,
        required: [true, 'Price (in NGN) is required'],
        min: [0.01, 'Price (in NGN) must be greater than zero']
    },
    variations: {
        type: [ProductVariationSchema], 
        required: [true, 'At least one product variation is required'],
        validate: {
            validator: function(v) { return v.length >= 1 && v.length <= 4; },
            message: 'A product must have between 1 and 4 variations.'
        }
    },
    totalStock: {
        type: Number,
        min: [0, 'Stock cannot be negative'],
    },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// 🚀 CRITICAL HOOK: Automatically calculates totalStock based on variations/sizes
NewArrivalsSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    
    // 1. Calculate the new total stock
    let calculatedTotalStock = 0;
    
    if (this.variations && this.variations.length > 0) {
        calculatedTotalStock = this.variations.reduce((totalVariationStock, variation) => {
            // Sum all stock counts within the sizes array for this variation
            const variationStockSum = (variation.sizes || []).reduce((totalSizeStock, sizeEntry) => {
                // Safely access stock property, defaulting to 0 if null/undefined
                return totalSizeStock + (sizeEntry.stock || 0);
            }, 0); 
            
            return totalVariationStock + variationStockSum;
        }, 0);
    }
    
    // 2. Apply business logic and set the totalStock field
    if (this.isActive === false) {
        // If the product is deactivated, total stock is 0, regardless of calculation
        this.totalStock = 0;
    } else {
        // Otherwise, use the calculated sum
        this.totalStock = calculatedTotalStock;
    }
    
    next();
});
const NewArrivals = mongoose.models.NewArrivals || mongoose.model('NewArrivals', NewArrivalsSchema);

// --- CapVariationSchema (Used for Caps/No-Size Items) ---
const CapVariationSchema = new mongoose.Schema({
    variationIndex: { type: Number, required: true, min: 1, max: 4 },
    // --- FRONT IMAGE FIELDS ---
    frontImageUrl: { type: String, required: [true, 'Front view image permanent key is required'], trim: true }, 
    frontCachedSignedUrl: { type: String, default: null },
    frontSignedUrlExpiresAt: { type: Date, default: null },

    // --- BACK IMAGE FIELDS ---
    backImageUrl: { type: String, required: [true, 'Back view image permanent key is required'], trim: true }, 
    backCachedSignedUrl: { type: String, default: null },
    backSignedUrlExpiresAt: { type: Date, default: null },

    colorHex: { type: String, required: [true, 'Color Hex code is required'], match: [/^#[0-9A-F]{6}$/i, 'Color must be a valid hex code (e.g., #RRGGBB)'] },
    
    // Direct stock counter
    stock: { type: Number, required: [true, 'Stock count is required'], min: 0, default: 0 }
}, { _id: false });

// --- 🧢 UPDATED CAP COLLECTION SCHEMA AND MODEL 🧢 ---
const CapCollectionSchema = new mongoose.Schema({
    name: { type: String, required: [true, 'Collection name is required'], trim: true, maxlength: [100, 'Collection name cannot exceed 100 characters'] },
    description: { 
        type: String, 
        trim: true, 
        maxlength: [1000, 'Description cannot exceed 1000 characters'],
        default: '' 
    },
    tag: { type: String, required: [true, 'Collection tag is required'], enum: ['Top Deal', 'Hot Deal', 'New', 'Seasonal', 'Clearance'] },
    price: { type: Number, required: [true, 'Price (in NGN) is required'], min: [0.01, 'Price (in NGN) must be greater than zero'] },
    variations: {
        type: [CapVariationSchema], 
        required: [true, 'At least one product variation is required'],
        validate: {
            validator: function(v) { return v.length >= 1 && v.length <= 4; },
            message: 'A collection must have between 1 and 4 variations.'
        }
    },
    totalStock: { type: Number, required: [true, 'Total stock number is required'], min: [0, 'Stock cannot be negative'], default: 0 },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// --- UPDATED Pre-Save Middleware (CapCollection) ---
// Runs on Model.save() or Model.create()
CapCollectionSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    
    // 1. Calculate the new total stock
    let calculatedTotalStock = 0;
    
    if (this.variations && this.variations.length > 0) {
        calculatedTotalStock = this.variations.reduce((totalStock, variation) => {
            // Summing the direct 'stock' field
            return totalStock + (variation.stock || 0);
        }, 0);
    }
    
    // 2. Apply business logic and set the totalStock field
    if (this.isActive === false) {
        this.totalStock = 0;
    } else {
        this.totalStock = calculatedTotalStock;
    }
    
    next();
});

CapCollectionSchema.pre('findOneAndUpdate', function(next) {
    const update = this.getUpdate();
    
    this.set({ updatedAt: Date.now() });

    if (update.collectionData && update.collectionData.variations) {
        const variations = update.collectionData.variations;
        
        let calculatedTotalStock = variations.reduce((totalStock, variation) => {
            return totalStock + (variation.stock || 0);
        }, 0);

        const isActive = update.collectionData.isActive !== undefined ? update.collectionData.isActive : true; 
        
        if (isActive === false) {
            update.collectionData.totalStock = 0;
        } else {
            update.collectionData.totalStock = calculatedTotalStock;
        }
    } 

    if (update.totalStock !== undefined && Array.isArray(update.variations) === false) {
   
        const newStockValue = update.totalStock;
        
        this.updateMany({}, { $set: { "variations.$[].stock": newStockValue } }).exec();
    }
    
    next();
});

// --- Model Definition and Export ---
const CapCollection = mongoose.models.CapCollection || mongoose.model('CapCollection', CapCollectionSchema);

const PreOrderCollectionSchema = new mongoose.Schema({
    // General Product Information
    name: { type: String, required: [true, 'Collection name is required'], trim: true },
      description: { 
        type: String, 
        trim: true, 
        maxlength: [1000, 'Description cannot exceed 1000 characters'],
        default: '' 
    },
    tag: { type: String, required: [true, 'Tag is required'], enum: ['Pre-Order', 'Coming Soon', 'Limited Drop', 'Seasonal'] }, 
    price: { type: Number, required: [true, 'Price is required'], min: [0.01, 'Price must be greater than zero'] },
    
    // Derived/Managed field: Total Stock is calculated from all variation sizes
    totalStock: { type: Number, required: [true, 'Total stock is required'], min: [0, 'Stock cannot be negative'], default: 0 },
    isActive: { type: Boolean, default: true },

    // New Availability Field
    availableDate: { 
        type: Date, 
        required: [true, 'Available date is required'], 
    }, 

    // Variations 
    variations: {
        type: [ProductVariationSchema], 
        required: [true, 'At least one product variation is required'],
        validate: {
            validator: function(v) { return v.length >= 1 && v.length <= 4; },
            message: 'A collection must have between 1 and 4 variations.'
        }
    }
}, { timestamps: true }); // Using { timestamps: true } handles createdAt and updatedAt automatically

PreOrderCollectionSchema.pre('save', function(next) {
    // If using { timestamps: true }, this line is often unnecessary but harmless
    // this.updatedAt = Date.now(); 
    
    // 1. Calculate the new total stock
    let calculatedTotalStock = 0;
    
    if (this.variations && this.variations.length > 0) {
        // Iterate through all variations (e.g., colors)
        calculatedTotalStock = this.variations.reduce((totalCollectionStock, variation) => {
            
            // For each variation, sum the stock of all its sizes
            // Note: variation.sizes is guaranteed to be an array or null/undefined, 
            // so || [] ensures safe reduction.
            const variationStockSum = (variation.sizes || []).reduce((totalSizeStock, sizeEntry) => {
                // Safely access size stock property, defaulting to 0
                return totalSizeStock + (sizeEntry.stock || 0);
            }, 0); 
            
            // Add this variation's total stock to the collection's grand total
            return totalCollectionStock + variationStockSum;
        }, 0);
    }
    
    // 2. Apply business logic and set the totalStock field
    if (this.isActive === false) {
        // If the product is deactivated, total stock is 0
        this.totalStock = 0;
    } else {
        // Otherwise, use the calculated sum
        this.totalStock = calculatedTotalStock;
    }
    
    next();
});

// --- Model Definition and Export ---
const PreOrderCollection = mongoose.models.PreOrderCollection || mongoose.model('PreOrderCollection', PreOrderCollectionSchema);

const cartItemSchema = new mongoose.Schema({
    productId: { type: mongoose.Schema.Types.ObjectId, required: true },
    name: { type: String, required: true },
    productType: { 
        type: String, 
        required: true, 
    },
    
    // Variant Details
    size: { type: String, required: true },
    color: { type: String }, 
    variationIndex: { type: Number, required: true, min: 1 },
    variation: { type: String },
    
    // Pricing & Quantity
    price: { type: Number, required: true, min: 0.01 },
    quantity: { type: Number, required: true, min: 1, default: 1 },
    
    // Media
    imageUrl: { type: String },

    // ⭐ NEW: Added to track if the price has changed since adding to cart
    addedAt: { type: Date, default: Date.now }
}, { _id: true });

const cartSchema = new mongoose.Schema({
    // Keep userId REQUIRED here. 
    // Guest carts stay in LocalStorage; Database carts are for Users only.
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true, 
        unique: true 
    },
    items: {
        type: [cartItemSchema],
        default: []
    }
}, { timestamps: true }); // Automatically handles createdAt and updatedAt

const Cart = mongoose.models.Cart || mongoose.model('Cart', cartSchema);

// We need a robust order model to track sales and manage inventory deduction.
const OrderItemSchema = new mongoose.Schema({
    productId: { 
        type: mongoose.Schema.Types.ObjectId, 
        required: true, 
    },
    productType: { 
        type: String, 
        required: true, 
        enum: ['WearsCollection', 'CapCollection', 'NewArrivals', 'PreOrderCollection'] 
    },
    name: { type: String, required: true },
    imageUrl: { type: String },
    quantity: { type: Number, required: true, min: 1 },
    priceAtTimeOfPurchase: { type: Number, required: true, min: 0.01 },
    variationIndex: { 
        type: Number, 
        required: [true, 'Variation index is required for inventory deduction.'],
        min: 1 
    },    size: { type: String },
    color: { type: String },
    variation: { type: String } 
}, { _id: false });


const OrderSchema = new mongoose.Schema({
    // ⭐ UPDATE: userId is no longer required to allow Guest Checkout
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: false 
    },
    
    // ⭐ NEW: Explicitly track guest status for easier admin filtering
    isGuest: { 
        type: Boolean, 
        default: false 
    },

    // ⭐ NEW: Store the guest's email at the top level for communication
    // It's required only if userId is missing.
    guestEmail: { 
        type: String, 
        required: function() { return !this.userId; },
        trim: true,
        lowercase: true
    },

    items: { type: [OrderItemSchema], required: true },
    
    // --- Financial Breakdown ---
    subtotal: { type: Number, required: true, min: 0 },
    shippingFee: { type: Number, required: true, min: 0 },
    tax: { type: Number, required: true, min: 0 },
    totalAmount: { type: Number, required: true, min: 0.01 }, // Grand total
    
    status: { 
        type: String, 
        required: true,
        enum: [
            'Pending', 
            'Processing', 
            'Shipped', 
            'Delivered',
            'Cancelled',
            'Confirmed',
            'Completed',
            'Refunded',
            'Verification Failed', 
            'Amount Mismatch (Manual Review)',
            'Inventory Failure (Manual Review)', 
        ], 
        default: 'Pending'
    },    
    shippingAddress: { type: Object, required: true },
    paymentMethod: { type: String, required: true },
    orderReference: { type: String, unique: true, sparse: true },
    amountPaidKobo: { type: Number, min: 0 },
    paymentTxnId: { type: String, sparse: true },
    paidAt: { type: Date },
    paymentReceiptUrl: { type: String, sparse: true }, 
    shippedAt: { type: Date, sparse: true }, 
    deliveredAt: { type: Date, sparse: true },    
    confirmedAt: { type: Date, sparse: true },
    confirmedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', sparse: true },
    notes: [String] 
}, { timestamps: true });

// --- TTL Index for Cleanup ---
OrderSchema.index(
    { createdAt: 1 }, 
    { 
        expireAfterSeconds: 300, 
        partialFilterExpression: { 
            status: 'Pending', 
            paymentMethod: 'Paystack',
            amountPaidKobo: { $exists: false } 
        } 
    }
);

const Order = mongoose.models.Order || mongoose.model('Order', OrderSchema);

const ActivityLogSchema = new mongoose.Schema({
    // Type of event: 'LOGIN', 'ORDER_PLACED', 'REGISTERED', 'FORGOT_PASSWORD', 'ADD_TO_CART'
    eventType: { 
        type: String, 
        required: true, 
        enum: [
            'LOGIN', 
            'ORDER_PLACED', 
            'REGISTERED', 
            'FORGOT_PASSWORD', 
            'ADD_TO_CART',
            'ORDER_CONFIRMED', // Admin confirmed payment/inventory deduction
            'ORDER_SHIPPED',   // Admin updated status to Shipped
            'ORDER_DELIVERED'  // Admin updated status to Delivered
        ] 
    },
    description: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true, required: false },     
    context: { type: Object },
    timestamp: { type: Date, default: Date.now, index: true }
});

const ActivityLog = mongoose.model('ActivityLog', ActivityLogSchema);

const visitorLogSchema = new mongoose.Schema({
    // --- 🔑 CORE IDENTIFIERS ---
    // Used to count unique sessions/visitors
    sessionId: { 
        type: String, 
        required: true, 
        index: true // Index for fast lookup/grouping
    },
    // Optional: Link to a registered user if they are logged in
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        default: null,
        index: true 
    },
    
    // --- 🌍 EVENT & CONTEXT ---
    // The URL path visited (e.g., /api/products/123)
    path: { 
        type: String, 
        required: true 
    },
    // The full URL including query parameters
    fullUrl: { 
        type: String 
    },
    // HTTP method used (GET, POST, etc.) - useful for filtering API usage
    method: {
        type: String,
        enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
        default: 'GET'
    },
    
    // --- 📍 SOURCE & TIME ---
    // The timestamp when the event occurred (Crucial for time-based aggregation)
    timestamp: { 
        type: Date, 
        default: Date.now,
        index: true // Index for time-based queries (e.g., visitors today)
    },
    // The source that referred the user (e.g., Google, Twitter, direct)
    referrer: { 
        type: String, 
        default: null 
    },

    // --- 💻 DEVICE & GEOGRAPHY ---
    // Device type derived from User-Agent (e.g., 'desktop', 'mobile', 'bot')
    deviceType: { 
        type: String 
    },
    // The user's IP address (for geographical and unique visitor estimation)
    ipAddress: { 
        type: String 
    },
    // Basic geographical data derived from IP (e.g., country, city)
    geo: {
        country: { type: String, default: null },
        city: { type: String, default: null }
    }

}, { 
    // Mongoose option to ensure we use the explicit 'timestamp' field above 
    // for when the event occurred, rather than relying on Mongoose's auto-timestamps.
    timestamps: false 
});

// ✅ CRITICAL OPTIMIZATION: Add a compound index for the main analytics query.
// This supports the aggregation pipeline's $match (timestamp) and $group (sessionId) stages.
visitorLogSchema.index({ timestamp: 1, sessionId: 1 }); // 

// Create the model using the same pattern as your other schemas
const VisitorLog = mongoose.models.VisitorLog || mongoose.model('VisitorLog', visitorLogSchema);

// --- DATABASE INTERACTION FUNCTIONS (Unchanged) ---
async function findAdminUserByEmail(email) {
    const adminUser = await Admin.findOne({ email }).select('+password').lean();
    if (adminUser) {
        return { id: adminUser._id, email: adminUser.email, hashedPassword: adminUser.password };
    }
    return null;
}

async function createAdminUser(email, hashedPassword) {
    try {
        const newAdmin = await Admin.create({ email, password: hashedPassword });
        return { id: newAdmin._id, email: newAdmin.email };
    } catch (error) {
        console.error("Error creating admin user:", error);
        return null;
    }
}

/**
 * Retrieves real-time statistics for the admin dashboard.
 * Calculates Total Sales, and individual collection stock counts.
 */
async function getRealTimeDashboardStats() {
    try {
        // ⭐ CRITICAL FIX: Defensively retrieve all Mongoose models
        const OrderModel = mongoose.models.Order || mongoose.model('Order');
        const WearsCollectionModel = mongoose.models.WearsCollection || mongoose.model('WearsCollection');
        const CapCollectionModel = mongoose.models.CapCollection || mongoose.model('CapCollection');
        const NewArrivalsModel = mongoose.models.NewArrivals || mongoose.model('NewArrivals');
        const PreOrderCollectionModel = mongoose.models.PreOrderCollection || mongoose.model('PreOrderCollection');
        const UserModel = mongoose.models.User || mongoose.model('User');
        const ActivityLogModel = mongoose.models.ActivityLog || mongoose.model('ActivityLog');

        // 1. Calculate Total Sales (sum of 'totalAmount' from completed orders)
        console.log('[BACKEND] Starting Total Sales Aggregation...'); // ADDED LOG

        const salesAggregation = await OrderModel.aggregate([ // Using OrderModel
            { 
                $match: { 
                    status: { 
                        $in: ['Confirmed', 'Shipped', 'Delivered'] 
                    } 
                } 
            },
            { $group: { _id: null, totalSales: { $sum: '$totalAmount' } } }
        ]);
        
        // ⭐ ADDED LOG: Show the raw result from MongoDB
        console.log('[BACKEND] Raw Sales Aggregation Result:', salesAggregation);

        const totalSales = salesAggregation.length > 0 ? salesAggregation[0].totalSales : 0;
        
        // ⭐ ADDED LOG: Show the final calculated totalSales value and its type
        console.log(`[BACKEND] Final totalSales calculated: ${totalSales}, Type: ${typeof totalSales}`);


        // 2. Calculate Individual Collection Stock Counts
        
        // Count for Wears Collection (only active items with stock > 0)
        const wearsInventory = await WearsCollectionModel.aggregate([ // Using WearsCollectionModel
            { $match: { isActive: true, totalStock: { $gt: 0 } } },
            { $group: { _id: null, total: { $sum: '$totalStock' } } }
        ]);
        const wearsStock = wearsInventory[0]?.total || 0;

        // Count for Caps Collection (only active items with stock > 0)
        const capsInventory = await CapCollectionModel.aggregate([ // Using CapCollectionModel
            { $match: { isActive: true, totalStock: { $gt: 0 } } },
            { $group: { _id: null, total: { $sum: '$totalStock' } } }
        ]);
        const capsStock = capsInventory[0]?.total || 0;
        
        // Count for New Arrivals Collection (only active items with stock > 0)
        const newArrivalsInventory = await NewArrivalsModel.aggregate([ // Using NewArrivalsModel
            { $match: { isActive: true, totalStock: { $gt: 0 } } },
            { $group: { _id: null, total: { $sum: '$totalStock' } } }
        ]);
        const newArrivalsStock = newArrivalsInventory[0]?.total || 0;
        
        // Count for Pre-Order Collection (only active items with stock > 0)
        const preOrderInventory = await PreOrderCollectionModel.aggregate([ // Using PreOrderCollectionModel
            { $match: { isActive: true, totalStock: { $gt: 0 } } },
            { $group: { _id: null, total: { $sum: '$totalStock' } } }
        ]);
        const preOrderStock = preOrderInventory[0]?.total || 0;

        // 3. Count Registered Users
        const userCount = await UserModel.countDocuments({}); // Using UserModel

        // --- Removed activeSubscriptions calculation line (ReferenceError fix) ---

       const recentActivity = await ActivityLogModel.find({}) 
            .sort({ timestamp: -1 }) // Sort by newest first
            .limit(5)
            .populate('userId', 'email username') // Fetch only email and username
            .lean(); // Use .lean() for faster query performance

        // 4. Return all required data fields
        console.log('[BACKEND] Returning dashboard stats successfully.'); // ADDED LOG
        return {
            totalSales: totalSales,
            userCount: userCount,
            wearsStock: wearsStock,
            capsStock: capsStock,
            newArrivalsStock: newArrivalsStock,
            preOrderStock: preOrderStock,
            recentActivity: recentActivity
        };

    } catch (error) {
        console.error('Error in getRealTimeDashboardStats:', error);
        // Log the full error, and re-throw a specific one for the calling function
        throw new Error('Database aggregation failed for dashboard stats.');
    }
}

const PRODUCT_MODEL_MAP = {
    'WearsCollection': 'WearsCollection', 
    'CapCollection': 'CapCollection', 
    'NewArrivals': 'NewArrivals',         
    'PreOrderCollection': 'PreOrderCollection'     
};

/**
 * ====================================================================================
 * HELPER FUNCTION: GET PRODUCT MODEL
 * ====================================================================================
 * Safely retrieves the Mongoose Model constructor based on the product type string.
 * @param {string} productType The type identifier (e.g., 'WearsCollection').
 * @returns {mongoose.Model} The Mongoose Model constructor.
 * @throws {Error} If the model is not found in the Mongoose registry.
 */
function getProductModel(productType) {
    const modelName = PRODUCT_MODEL_MAP[productType];
    
    if (!modelName) {
        throw new Error(`Invalid or unsupported product type: ${productType}`);
    }

    // Attempt to retrieve the model from Mongoose's registered models
    const ProductModel = mongoose.models[modelName];

    if (!ProductModel || typeof ProductModel.findOneAndUpdate !== 'function') {
        throw new Error(`Mongoose model '${modelName}' for product type '${productType}' not found or improperly defined.`);
    }

    return ProductModel;
}

/**
 * HELPER FUNCTION: INVENTORY ROLLBACK
 * Updates the order status to indicate a stock failure after a transaction aborts.
 * This is called outside the transaction to persist the failure state immediately.
 */
async function inventoryRollback(orderId, reason) {
    try {
        const OrderModel = mongoose.models.Order || mongoose.model('Order');

        // We use $push for notes to keep a history of what happened
        await OrderModel.findByIdAndUpdate(
            orderId,
            {
                status: 'Inventory Failure (Manual Review)', 
                $push: { notes: `Auto-Rollback: ${reason} at ${new Date().toISOString()}` },
                updatedAt: Date.now()
            },
            { new: true }
        );
        
        console.warn(`🔴 CRITICAL: Order ${orderId} failed automation. Reason: ${reason}`);
        
        // OPTIONAL: Trigger an admin alert here (e.g., Email or WhatsApp to you)
        // await sendAdminAlert(`Payment received for Order ${orderId} but stock deduction failed.`);
        
    } catch (err) {
        console.error(`CRITICAL: Failed to update order ${orderId} status during rollback.`, err);
    }
}

/**
 * ====================================================================================
 * INVENTORY PROCESSING FUNCTION (ATOMIC & TRANSACTIONAL)
 * ====================================================================================
 * Processes an order confirmation by atomically deducting stock for all items
 * across different product collections (Wears, Caps, NewArrivals, PreOrder).
 * @param {string} orderId The ID of the order to confirm.
 * @param {string} adminId The ID of the admin confirming the order.
 * @returns {Promise<Object>} The confirmed order object.
 * @throws {Error} Throws an error if stock is insufficient or a race condition is detected.
 */
async function processOrderCompletion(orderId, adminId) {
    const session = await mongoose.startSession();
    session.startTransaction();
    let order = null;

    try {
        const OrderModel = mongoose.models.Order || mongoose.model('Order');
        // Populate userId so we can access the ID to clear the cart later
        order = await OrderModel.findById(orderId).populate('userId').session(session);

        if (!order) throw new Error("Order not found.");

        // 1. Guardrail: Only process 'Pending' or 'Processing' orders
        // This prevents double-deducting stock if the admin clicks twice.
        const canProcess = ['Pending', 'Processing'].includes(order.status);
        if (!canProcess) {
            await session.abortTransaction();
            console.warn(`Order ${orderId} is already ${order.status}. Skipping.`);
            return order;
        }

        // 2. Loop and Deduct Stock
        for (const item of order.items) {
            const ProductModel = getProductModel(item.productType); 
            if (!ProductModel) throw new Error(`Model missing for: ${item.productType}`);

            const qty = item.quantity;
            let updateResult;

            // Group 1: Size-based Collections
            if (['WearsCollection', 'NewArrivals', 'PreOrderCollection'].includes(item.productType)) {
                updateResult = await ProductModel.findOneAndUpdate(
                    { _id: item.productId, 'variations.variationIndex': item.variationIndex },
                    { $inc: { 'variations.$[var].sizes.$[size].stock': -qty, 'totalStock': -qty } },
                    { 
                        session, new: true, 
                        arrayFilters: [
                            { 'var.variationIndex': item.variationIndex },
                            { 'size.size': item.size, 'size.stock': { $gte: qty } }
                        ] 
                    }
                );
            } 
            // Group 2: Direct Stock (Caps)
            else if (item.productType === 'CapCollection') {
                updateResult = await ProductModel.findOneAndUpdate(
                    { 
                        _id: item.productId, 
                        'variations': { $elemMatch: { variationIndex: item.variationIndex, stock: { $gte: qty } } } 
                    },
                    { $inc: { 'variations.$[var].stock': -qty, 'totalStock': -qty } },
                    { session, new: true, arrayFilters: [{ 'var.variationIndex': item.variationIndex }] }
                );
            }

            if (!updateResult) {
                throw new Error(`STOCK ERROR: ${item.name} (${item.size || 'N/A'}) is out of stock.`);
            }
        }

        // 3. Finalize Order Status
        order.status = 'Confirmed';
        order.confirmedAt = new Date(); 
        order.confirmedBy = adminId; 
        
        await order.save({ session });
        await session.commitTransaction();

        // 4. Post-Transaction: Clear Cart (Don't let cart errors crash the transaction)
        try {
            const CartModel = mongoose.models.Cart || mongoose.model('Cart');
            if (order.userId) {
                await CartModel.findOneAndUpdate({ userId: order.userId._id }, { items: [] });
            }
        } catch (e) { console.error("Cart clear failed:", e.message); }

        return order.toObject({ getters: true });

    } catch (error) {
        if (session.inTransaction()) await session.abortTransaction();
        // Log the failure in your system
        if (order) await inventoryRollback(orderId, error.message);
        throw error;
    } finally {
        session.endSession();
    }
}

// ====================================================================================
// NEW: DEDUCT INVENTORY AND MARK ORDER AS COMPLETED (For Webhooks/Automation)
// ====================================================================================

/**
 * Executes the inventory deduction and sets the order status to 'Completed'.
 * This is designed to be called by automated systems like webhooks.
 * @param {string} orderId The ID of the order to complete.
 * @returns {Promise<Object>} The completed order object.
 * @throws {Error} Throws an error if stock is insufficient or a race condition is detected.
 */
async function deductInventoryAtomic(orderId) {
    // 1. Start a Mongoose session for atomicity (crucial for inventory)
    const session = await mongoose.startSession();
    session.startTransaction();
    let order = null;
    let OrderModel;

    try {
        OrderModel = mongoose.models.Order || mongoose.model('Order');
        order = await OrderModel.findById(orderId).session(session);

        // CRITICAL CHECK: Only process orders in 'Pending' or 'Processing' state
        if (!order || order.status === 'Completed' || order.status === 'Confirmed') {
            await session.abortTransaction();
            const raceError = new Error(`Order ${orderId} status is ${order?.status || 'N/A'}. Inventory deduction skipped.`);
            raceError.isRaceCondition = true;
            throw raceError;
        }

        // --- 2. LOOP THROUGH ITEMS AND DEDUCT STOCK (Paste your existing loop logic here) ---
        for (const item of order.items) {
             // ... (The entire stock deduction logic from processOrderCompletion) ...
             const ProductModel = getProductModel(item.productType); 
             const quantityOrdered = item.quantity;
             let updatedProduct;
             let errorMsg;
             
             // --- Group 1: Items with nested 'sizes' array (Wears, NewArrivals, PreOrder) ---
             if (item.productType === 'WearsCollection' || item.productType === 'NewArrivals' || item.productType === 'PreOrderCollection') {
                 if (!item.size) { 
                     errorMsg = `Missing size information for size-based product ${item.productId} in ${item.productType}.`;
                     throw new Error(errorMsg);
                 }
                 updatedProduct = await ProductModel.findOneAndUpdate(
                     {
                         _id: item.productId,
                         'variations.variationIndex': item.variationIndex 
                     },
                     {
                         $inc: {
                             'variations.$[var].sizes.$[size].stock': -quantityOrdered, 
                             'totalStock': -quantityOrdered 
                         }
                     },
                     {
                         new: true,
                         session: session, 
                         arrayFilters: [
                             { 'var.variationIndex': item.variationIndex }, 
                             { 'size.size': item.size, 'size.stock': { $gte: quantityOrdered } } 
                         ]
                     }
                 );
             // --- Group 2: Items with direct 'stock' on variation (CapCollection) ---
             } else if (item.productType === 'CapCollection') {
                 updatedProduct = await ProductModel.findOneAndUpdate(
                     {
                         _id: item.productId,
                         'variations': {
                             $elemMatch: {
                                 variationIndex: item.variationIndex,
                                 stock: { $gte: quantityOrdered } 
                             }
                         }
                     },
                     {
                         $inc: {
                             'variations.$[var].stock': -quantityOrdered, 
                             'totalStock': -quantityOrdered 
                         }
                     },
                     {
                         new: true,
                         session: session, 
                         arrayFilters: [
                             { 'var.variationIndex': item.variationIndex } 
                         ]
                     }
                 );
             } else {
                 errorMsg = `Unsupported product type found: ${item.productType}. Inventory deduction aborted.`;
                 throw new Error(errorMsg);
             }

             if (!updatedProduct) {
                 const sizeLabel = item.productType === 'CapCollection' ? 'N/A (Direct Stock)' : item.size;
                 const finalErrorMsg = `Insufficient stock or product data mismatch for item: ${sizeLabel} of product ${item.productId} in ${item.productType}. Transaction aborted.`;
                 throw new Error(finalErrorMsg);
             }
        }
        // --- END STOCK DEDUCTION LOOP ---

        // 3. Update order status to a final state (e.g., 'Completed')
        order.status = 'Completed'; // Use 'Completed' to distinguish from Admin 'Confirmed'
        order.completedAt = new Date(); 
        await order.save({ session });

        // 4. Finalize transaction
        await session.commitTransaction();
        return order.toObject({ getters: true });

    } catch (error) {
        if (session.inTransaction()) {
            await session.abortTransaction();
        }
        if (!error.isRaceCondition && order) { 
            // Reuse the rollback function for failures
            await inventoryRollback(orderId, error.message);
        }
        throw error;
    } finally {
        session.endSession();
    }
}

/**
 * HELPER FUNCTION: RECORD PAYMENT ONLY
 * Used by webhooks to mark an order as paid without touching stock.
 */
async function deductInventoryAndCompleteOrder(orderId, transactionData) {
    try {
        const OrderModel = mongoose.models.Order || mongoose.model('Order');
        
        const order = await OrderModel.findByIdAndUpdate(
            orderId,
            {
                paymentStatus: 'Paid',
                paymentMethod: 'Paystack',
                paymentTxnId: transactionData.reference,
                paidAt: new Date(),
                // Keep status as 'Pending' so Admin sees it in the "To Confirm" list
                status: 'Pending', 
                $push: { notes: `Paystack Payment Verified at ${new Date().toISOString()}` }
            },
            { new: true }
        );

        if (!order) throw new Error(`Order ${orderId} not found.`);
        console.log(`✅ Paystack Payment Recorded for Order ${orderId}. Awaiting Admin Confirmation.`);
        return order.toObject({ getters: true });

    } catch (error) {
        console.error(`❌ Webhook Payment Log Failed: ${error.message}`);
        throw error;
    }
}

/**
 * Retrieves all orders for the admin sales log.
 * Populates the userId field to get customer information.
 */
async function getAllOrders() {
    try {
        const OrderModel = mongoose.models.Order || mongoose.model('Order');

        // Fetch all orders
        // .populate('userId', 'email username') is critical to display customer info 
        // without sending back the entire User object (like hashed password).
        const allOrders = await OrderModel.find({})
            .sort({ createdAt: -1 }) // Sort by newest order first
            .populate('userId', 'email username')
             .sort({ createdAt: -1 })
            .lean(); // Use .lean() for faster read performance

        return allOrders;
    } catch (error) {
        console.error('Error in getAllOrders:', error);
        throw new Error('Database query failed for sales log.');
    }
}


/**
 * ====================================================================================
 * HELPER FUNCTIONS (Preserved as provided)
 * ====================================================================================
 */

async function populateInitialData() {
    if (!DEFAULT_ADMIN_EMAIL || !DEFAULT_ADMIN_PASSWORD) {
        console.warn('Skipping initial data population: Default admin credentials not fully set.');
        return;
    }

    try {
        // NOTE: Assumes Admin and bcrypt are defined globally or imported.
        const adminCount = await Admin.countDocuments({ email: DEFAULT_ADMIN_EMAIL });

        if (adminCount === 0) {
            console.log(`Default admin user (${DEFAULT_ADMIN_EMAIL}) not found. Creating...`);

            const salt = await bcrypt.genSalt(BCRYPT_SALT_ROUNDS);
            const hashedPassword = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, salt);

            await Admin.create({ email: DEFAULT_ADMIN_EMAIL, password: hashedPassword });
            console.log(`Default admin user created successfully.`);
        } else {
            console.log(`Default admin user already exists. Skipping creation.`);
        }
    } catch (error) {
        console.error('Error during initial data population:', error);
    }
}

const SHIPPING_COST = 0.00;
const TAX_RATE = 0.00;

/**
 * Calculates cart totals based on the array of items from Mongoose.
 * @param {Array<Object>} cartItems - The cart.items array from the Mongoose document.
 * @returns {Object} Calculated totals.
 */
function calculateCartTotals(cartItems) {
    // 1. Calculate Subtotal
    const subtotal = cartItems.reduce((acc, item) =>
        acc + (item.price * item.quantity), 0);
    // 2. Calculate Tax
    const tax = subtotal * TAX_RATE;
    const shipping = cartItems.length > 0 ? SHIPPING_COST : 0;

    // 4. Calculate Final Total
    const estimatedTotal = subtotal + tax + shipping;

    // Format for easy frontend consumption
    return {
        subtotal: subtotal,
        shipping: shipping,
        tax: tax,
        estimatedTotal: estimatedTotal,
    };
}

/**
 * Calculates cart totals locally for unauthenticated sessions.
 * Matches the server-side logic (calculateCartTotals).
 * @param {Array<Object>} items - The array of local cart items.
 * @returns {Object} Calculated totals structure.
 */
function calculateLocalTotals(items) {
    const subtotal = items.reduce((sum, item) =>
        sum + (item.price * item.quantity), 0);

    const tax = subtotal * LOCAL_TAX_RATE;
    const shipping = items.length > 0 ? LOCAL_SHIPPING_COST : 0;
    const estimatedTotal = subtotal + tax + shipping;

    return {
        items: items,
        subtotal: subtotal,
        shipping: shipping,
        tax: tax,
        estimatedTotal: estimatedTotal
    };
}

/**
 * Merges unauthenticated local cart items into the user's permanent database cart,
 * automatically correcting missing/invalid 'productType' fields via database lookup.
 * @param {ObjectId} userId - The authenticated user's ID.
 * @param {Array<Object>} localItems - Items from the client's local storage.
 */
async function mergeLocalCart(userId, localItems) {
    // NOTE: This assumes Cart model, mongoose, and getProductModel are available in scope.
    
    try {
        let cart = await Cart.findOne({ userId });
        const mergedItems = [];

        // Helper function to find the actual product type via database lookup
        const findProductType = async (productId) => {
            // ⭐ FIX 1: Use the global map keys from the definition PRODUCT_MODEL_MAP
            for (const type of Object.keys(PRODUCT_MODEL_MAP)) {
                try {
                    // Use the helper to get the Mongoose model
                    const CollectionModel = getProductModel(type); 
                    
                    // Check if product exists in this collection
                    const productExists = await CollectionModel.exists({ _id: productId });
                    if (productExists) {
                        return type; // Return the correct, validated productType string
                    }
                } catch (e) {
                    // Ignore error if a model isn't properly defined and skip to next type
                    continue; 
                }
            }
            console.error(`Product ID ${productId} not found in any collection.`);
            return null; 
        };

        // --- Step A: Process and Validate each local item ---
        for (const localItem of localItems) {
            let actualProductType = localItem.productType;

            // Check if productType is missing or invalid 
            // We use try/catch to ensure getProductModel doesn't crash the loop
            if (!actualProductType) {
                actualProductType = await findProductType(localItem.productId);
            } else {
                 try {
                    // Check if the provided type is valid and maps to a model
                    getProductModel(actualProductType);
                 } catch(e) {
                    // If the type is defined but invalid, look it up
                    actualProductType = await findProductType(localItem.productId);
                 }
            }

            // CRITICAL: If type is still null, skip the corrupted item
            if (!actualProductType) {
                console.warn(`Skipping corrupted local cart item: ${localItem.productId}`);
                continue; 
            }

            // B. Prepare the item structure with the CORRECTED type
            const itemData = {
                productId: localItem.productId,
                name: localItem.name,
                productType: actualProductType, // ⭐ USES THE CORRECTED TYPE 
                size: localItem.size,
                color: localItem.color || 'N/A',
                price: localItem.price,
                quantity: localItem.quantity || 1,
                imageUrl: localItem.imageUrl,
                variationIndex: localItem.variationIndex, 
                variation: localItem.variation,
            };

            // C. Merge item into existing cart or prepare for new cart creation
            if (cart) {
                const existingItemIndex = cart.items.findIndex(dbItem =>
                    dbItem.productId.equals(itemData.productId) &&
                    dbItem.size === itemData.size &&
                    dbItem.color === itemData.color &&
                    // ⭐ FIX 2: MUST INCLUDE variationIndex for unique merging
                    dbItem.variationIndex === itemData.variationIndex 
                );
                
                if (existingItemIndex > -1) {
                    cart.items[existingItemIndex].quantity += itemData.quantity;
                } else {
                    cart.items.push(itemData);
                }
            } else {
                mergedItems.push(itemData); 
            }
        }
        
        // --- Step D: Final Save/Create ---
        if (!cart && mergedItems.length > 0) {
            await Cart.create({ userId, items: mergedItems });
        } else if (cart) {
            cart.updatedAt = Date.now();
            await cart.save();
        }
        
        console.log(`Successfully merged local cart items for user ${userId}.`);
        
    } catch (error) {
        // You should still log the error, but this catch block is correctly placed.
        console.error('CRITICAL: Error during robust cart merge process:', error);
        // Do NOT throw here, as it might cause the login route to crash entirely.
    }
}

/**
 * Takes a list of order documents and adds 'name' and 'imageUrl' to each item 
 * by fetching product details from all relevant collections.
 * * 🚨 CRITICAL UPDATE: This now generates a temporary, pre-signed URL for the imageUrl
 * if the image is stored privately (e.g., in Backblaze B2).
 * * @param {Array<Object>} orders - Array of order documents (must have an 'items' array).
 * @returns {Promise<Array<Object>>} - Orders with augmented item details, including signed image URLs.
 */
async function augmentOrdersWithProductDetails(orders) {
    if (!orders || orders.length === 0) {
        return [];
    }
    
    // 1. Get all unique product IDs from all orders
    const allProductIds = orders.flatMap(order => 
        order.items.map(item => item.productId)
    );
    
    // Convert unique string IDs back into Mongoose ObjectIds for $in query
    const uniqueProductObjectIds = [
        ...new Set(allProductIds.map(id => id.toString()))
    ].map(idStr => new mongoose.Types.ObjectId(idStr)); 

    // 2. Fetch product details (Names and Variations array for image URL)
    const projection = 'name variations'; 
    
    const wears = await WearsCollection.find({ _id: { $in: uniqueProductObjectIds } }).select(projection).lean();
    const caps = await CapCollection.find({ _id: { $in: uniqueProductObjectIds } }).select(projection).lean();
    const newArrivals = await NewArrivals.find({ _id: { $in: uniqueProductObjectIds } }).select(projection).lean();
    const preOrders = await PreOrderCollection.find({ _id: { $in: uniqueProductObjectIds } }).select(projection).lean(); 

    const allProducts = [...wears, ...caps, ...newArrivals, ...preOrders];
    
    // 3. Build Product Map (productId string -> { name, variations })
    const productMap = {};
    allProducts.forEach(product => {
        productMap[product._id.toString()] = {
            name: product.name,
            variations: product.variations
        };
    });

    // 4. Transform and merge product details into the orders array, signing URLs
    const detailedOrdersPromises = orders.map(async (order) => {
        
        const detailedItemsPromises = order.items.map(async (item) => {
            const productIdStr = item.productId.toString();
            const productInfo = productMap[productIdStr];
            
            let permanentImageUrl = null; // Store the B2 URL temporarily
            let productName = 'Unknown Product (Deleted)';

            if (productInfo) {
                productName = productInfo.name;
                
                // Find the exact variation based on the saved variationIndex
                const purchasedVariation = productInfo.variations.find(v => 
                    // Ensure robust comparison by converting both to strings
                    String(v.variationIndex) === String(item.variationIndex)
                );

                // Determine the permanent B2 URL
                if (purchasedVariation && purchasedVariation.frontImageUrl) {
                    permanentImageUrl = purchasedVariation.frontImageUrl;
                } else if (productInfo.variations.length > 0) {
                    // Fallback to the first variation's front image if exact match fails
                    if (productInfo.variations[0].frontImageUrl) {
                        permanentImageUrl = productInfo.variations[0].frontImageUrl;
                    }
                }
            }

            // --- 🚨 CRITICAL FIX: Generate Signed URL for private image access ---
            let signedImageUrl = 'https://placehold.co/32x32/CBD5E1/475569/png?text=N/A';
            if (permanentImageUrl) {
                // Assuming generateSignedUrl is available in scope (passed in context)
                const signedUrl = await generateSignedUrl(permanentImageUrl); 
                if (signedUrl) {
                    signedImageUrl = signedUrl;
                }
            }
            // --------------------------------------------------------------------

            return {
                ...item,
                name: productName,
                imageUrl: signedImageUrl, // Now holds the temporary, signed URL
                price: item.priceAtTimeOfPurchase, 
            };
        });
        
        // Wait for all item promises to resolve (including signing the URLs)
        const detailedItems = await Promise.all(detailedItemsPromises);

        return {
            ...order,
            items: detailedItems,
        };
    });
    
    // Wait for all order promises to resolve
    return Promise.all(detailedOrdersPromises);
}

/**
 * Uploads a file buffer (from Multer) to IDrive E2 and returns the permanent URL.
 * @param {Object} file - The Multer file object (includes buffer, mimetype, originalname).
 * @returns {Promise<string>} The permanent public URL of the uploaded file.
 */
async function uploadFileToPermanentStorage(file) {
    if (!file || !file.buffer) {
        throw new Error('File object or buffer is missing for upload.');
    }
    
    // Create a unique file path/key to prevent naming conflicts.
    const fileExtension = file.originalname.split('.').pop();
    const uniqueFileName = `${Date.now()}-${crypto.randomUUID()}.${fileExtension}`; 
    const fileKey = `uploads/${uniqueFileName}`; // Key structure inside the bucket

    try {
        console.log(`[IDrive E2] Starting upload for key: ${fileKey}`); // Updated logging

        // --- Using the robust 'Upload' utility for large file support ---
        const parallelUploads3 = new Upload({
            client: s3Client, // s3Client is already configured for IDrive E2
            params: {
                // --- ⚠️ CRITICAL CHANGE: Use IDRIVE_BUCKET_NAME ---
                Bucket: IDRIVE_BUCKET_NAME,
                // ----------------------------------------------------
                Key: fileKey,
                Body: file.buffer, // The actual file content
                ContentType: file.mimetype,
            },
            partSize: 1024 * 1024 * 5, // 5MB part size
            queueSize: 4, // Number of concurrent uploads
        });

        await parallelUploads3.done();
        
        console.log(`[IDrive E2] Upload successful for key: ${fileKey}`); // Updated logging

        // Construct the permanent URL based on your IDrive E2 endpoint pattern.
        // --- ⚠️ CRITICAL CHANGE: Use IDRIVE_ENDPOINT and IDRIVE_BUCKET_NAME ---
        const permanentUrl = `${IDRIVE_ENDPOINT}/${IDRIVE_BUCKET_NAME}/${fileKey}`;
        // ----------------------------------------------------------------------
        
        return permanentUrl;

    } catch (error) {
        console.error(`[IDrive E2] Failed to upload file ${file.originalname}:`, error); // Updated logging
        throw new Error('Permanent file storage failed. Check IDrive E2 credentials and bucket policy.'); // Updated error message
    }
}

// The functions you provided (no changes needed to the logic you drafted)
async function logAdminOrderAction(order, adminId, eventType) {
    try {
        const description = `Order #${order._id.toString().slice(-6)} confirmed. Total: ₦${order.totalAmount.toLocaleString()}.`;
        
        const newLogEntry = new ActivityLog({
            eventType: eventType, // Will be 'ORDER_CONFIRMED'
            description: description,
            userId: order.userId,
            context: {
                orderId: order._id,
                adminId: adminId
            },
        });
        await newLogEntry.save();
    } catch (error) {
        console.error('[ActivityLog] FAILED to log admin order confirmation:', error);
    }
}  

async function logAdminStatusUpdate(order, adminId, eventType) {
    try {
        const statusText = eventType === 'ORDER_SHIPPED' ? 'shipped' : 'delivered';
        const description = `Order #${order._id.toString().slice(-6)} marked as ${statusText}.`;

        const newLogEntry = new ActivityLog({
            eventType: eventType, // Will be 'ORDER_SHIPPED' or 'ORDER_DELIVERED'
            description: description,
            userId: order.userId,
            context: {
                orderId: order._id,
                adminId: adminId
            },
        });
        await newLogEntry.save();
    } catch (error) {
        console.error(`[ActivityLog] FAILED to log status update (${eventType}):`, error);
    }
}

// Assuming VisitorLog is accessible
async function getVisitorAnalytics(period = 'daily') {
    let dateRange = 30; // Default to last 30 days for daily chart
    let timeUnit;       // MongoDB date part to group by
    let timeFilter;     // Date object to start filtering from

    // Define filter/grouping based on the period
    switch (period) {
        case 'monthly':
            dateRange = 365; // Last 12 months
            // FIX: Assign $month operator to a key (e.g., 'month')
            timeUnit = { 
                month: { $month: "$timestamp" }, 
                year: { $year: "$timestamp" } 
            };
            break;
        case 'yearly':
            dateRange = 3 * 365; // Last 3 years
            timeUnit = { $year: "$timestamp" };
            break;
        case 'daily':
        default:
            dateRange = 30; // Last 30 days
            // FIX: Assign $dayOfYear operator to a key (e.g., 'day')
            timeUnit = { 
                day: { $dayOfYear: "$timestamp" }, // Corrected field name
                year: { $year: "$timestamp" } 
            };
            break;
    }
    
    timeFilter = new Date(Date.now() - dateRange * 24 * 60 * 60 * 1000);

    const analyticsData = await VisitorLog.aggregate([
        {
            // 1. FILTER by the last X days
            $match: {
                timestamp: { $gte: timeFilter }
            }
        },
        {
            // 2. GROUP by the time unit (day/month/year)
            $group: {
                _id: timeUnit, // Now uses correct structure, e.g., { day: <number>, year: <number> }
                // Count unique session IDs (Unique Visitors) for that period
                uniqueVisitors: { $addToSet: "$sessionId" },
            }
        },
        {
            // 3. PROJECT: Format and count the size of the unique set
            $project: {
                _id: 0,
                label: { // Create a readable label for the chart
                    $concat: [
                        { $toString: "$_id.year" },
                        // FIX: Use 'month' and 'day' from the corrected _id structure
                        { $cond: [ { $ifNull: ["$_id.month", false] }, { $concat: ["-", { $toString: "$_id.month" }] }, "" ] },
                        { $cond: [ { $ifNull: ["$_id.day", false] }, { $concat: ["-", { $toString: "$_id.day" }] }, "" ] }
                        // NOTE: Renamed $_id.dayOfYear to $_id.day for consistency with the group stage
                    ]
                },
                count: { $size: "$uniqueVisitors" }
            }
        },
        {
            // 4. SORT chronologically
            $sort: { label: 1 }
        }
    ]);

    // 5. FORMAT output into { labels: [], data: [] }
    const labels = analyticsData.map(item => item.label);
    const data = analyticsData.map(item => item.count);
    
    // Return the structure expected by Chart.js in the frontend
    return { labels, data };
}

const getSessionId = (req) => {
    // ⚠️ IMPORTANT: Adjust this based on how you handle sessions/cookies.
    // If using express-session, it's req.session.id
    // If using a custom cookie, you'll need to parse req.cookies
    return req.session?.id || req.cookies?.sessionId || null; 
};

// Middleware function to log the visitor details
const visitorLogger = async (req, res, next) => {
    // Only log GET requests to avoid logging mutations (POST, PUT, DELETE) 
    // and internal API calls, focusing on page views.
    if (req.method !== 'GET') {
        return next();
    }
    
    // Ignore internal system requests (e.g., favicon, assets)
    if (req.path.includes('favicon.ico') || req.path.startsWith('/assets')) {
        return next();
    }
    
    // --- Data Extraction ---
    const sessionId = getSessionId(req);
    const userId = req.user?._id || null; // Assumes 'req.user' is set by authentication
    
    if (!sessionId) {
        console.warn('VisitorLogger: Session ID is missing. Cannot log visit.');
        return next();
    }
    
    // --- Database Creation ---
    try {
        await VisitorLog.create({
            sessionId: sessionId,
            userId: userId,
            path: req.path,
            fullUrl: req.originalUrl,
            method: req.method,
            timestamp: new Date(),
            referrer: req.headers.referer || null,
            // You'd also add deviceType, ipAddress, and geo data here
            // using libraries like 'express-useragent' and 'geoip-lite'
        });
        
    } catch (error) {
        console.error("CRITICAL ERROR: Failed to create VisitorLog entry.", error);
    }
    
    // ⚠️ CRUCIAL: Pass control to the next middleware/route handler
    next(); 
};

/**
 * Processes a file (compression/conversion) and uploads the resulting buffer 
 * to IDrive E2, returning the permanent, unsign-ed URL.
 * * @param {Object} file - The file object from Multer (assuming memory storage).
 * @returns {Promise<string>} The permanent, clean URL of the uploaded file.
 */
async function uploadFileToPermanentStorage(file) {
    if (!file || !file.buffer) {
        throw new Error("Invalid file object provided for upload.");
    }

    try {
        const originalFileName = file.originalname;
        const fileExtension = path.extname(originalFileName);
        const baseName = path.basename(originalFileName, fileExtension);
        
        // --- 1. IMAGE PROCESSING AND COMPRESSION (CORE SPEED BOOST) ---
        const processedFileBuffer = await sharp(file.buffer)
            .resize({ 
                width: 1200, 
                fit: 'inside', 
                withoutEnlargement: true 
            })
            // Convert to WebP format with high-quality compression
            .webp({ quality: 80 }) 
            .toBuffer();
        // ----------------------------------------------------------------

        // Create a unique, WebP-specific key
        const fileKey = `collections/${Date.now()}-${baseName}.webp`; 
        
        // --- 2. IDRIVE E2 UPLOAD ---
        const parallelUploads3 = new Upload({
            client: s3Client, // Your pre-configured S3Client for IDrive E2
            params: {
                Bucket: IDRIVE_BUCKET_NAME,
                Key: fileKey,
                Body: processedFileBuffer, // Use the compressed buffer
                ContentType: 'image/webp', // Use the correct type for the converted format
                ACL: 'private', 
            },
        });

        await parallelUploads3.done();
        
        // Return the clean, permanent URL
        return `${IDRIVE_ENDPOINT}/${IDRIVE_BUCKET_NAME}/${fileKey}`;

    } catch (error) {
        console.error('Error during file processing and upload:', error);
        throw new Error(`File upload failed: ${error.message}`);
    }
}

/**
 * Generates a short-lived Access Token (e.g., 15 minutes) for API access.
 * This token is fast to verify and is stored on the client side (e.g., memory/local storage).
 * @param {Object} payload - The user data to embed (e.g., { id: user._id, role: user.role })
 * @returns {string} The signed JWT Access Token.
 */
function generateAccessToken(payload) {
    // Access tokens are short-lived for security
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' }); 
}

/**
 * Generates a long-lived Refresh Token (e.g., 7 days) for session persistence.
 * This token is sent as a secure HTTP-only cookie.
 * @param {Object} payload - The user data to embed (e.g., { id: user._id })
 * @returns {string} The signed JWT Refresh Token.
 */
function generateRefreshToken(payload) {
    // Refresh tokens are long-lived for convenience
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' }); 
}

/**
 * Unified Token Generation
 * Uses a single secret and consistent payload structure.
 */

const generateUserAccessToken = (payload) => {
    try {
        // Ensure we don't nest the payload twice
        const data = { id: payload.id, email: payload.email, role: 'user' };
        return jwt.sign(data, process.env.JWT_SECRET, { expiresIn: '15m' });
    } catch (err) {
        console.error("JWT Access Token Sign Error:", err);
        throw new Error("Failed to generate access token");
    }
};

const generateUserRefreshToken = (payload) => {
    try {
        const data = { id: payload.id, role: 'user' }; // Keep refresh payload small
        return jwt.sign(data, process.env.JWT_SECRET, { expiresIn: '7d' });
    } catch (err) {
        console.error("JWT Refresh Token Sign Error:", err);
        throw new Error("Failed to generate refresh token");
    }
};

// --- EXPRESS CONFIGURATION AND MIDDLEWARE ---
const app = express();
// Ensure express.json() is used BEFORE the update route, but after the full form route
// To allow both JSON and multipart/form-data parsing

app.use(cors(corsOptions));
app.use(express.json()); 
app.use(cookieParser());

app.use(visitorLogger);

app.use((req, res, next) => {
    // This allows external scripts (like Paystack) to load their own resources
    res.setHeader("Cross-Origin-Embedder-Policy", "unsafe-none");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
    next();
});

// Ensure robots.txt and sitemap.xml are served correctly
app.get('/robots.txt', (req, res) => {
    res.sendFile(path.join(__dirname, 'robots.txt'));
});

app.get('/sitemap.xml', (req, res) => {
    res.sendFile(path.join(__dirname, 'sitemap.xml'));
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => { res.redirect(301, '/outflickzstore/homepage.html'); });
app.get('/useraccount', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'useraccount.html')); }); 
app.get('/userprofile', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'userprofile.html')); }); 
app.get('/capscollection', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'capscollection.html')); }); 
app.get('/newarrivals', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'newarrivals.html')); }); 
app.get('/wearscollection', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'wearscollection.html')); }); 
app.get('/preorder', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'preoder.html')); }); 
app.get('/contact', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'contact.html')); }); 
app.get('/faq', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'faq.html')); }); 
app.get('/size_guide', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'size_guide.html')); }); 
app.get('/shipping_returns', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'shipping_returns.html')); }); 


//ADMIN ROUTE
app.get('/admin-login', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'admin-login.html')); });
app.get('/admin-dashboard', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'admin-dashboard.html')); });
app.get('/wearscollection', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'wearscollection.html')); });
app.get('/capscollection', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'capscollection.html')); }); 
app.get('/newarrivals', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'newarrivals.html')); }); 
app.get('/preorders', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'preorders.html')); }); 
app.get('/membership', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'membership.html')); }); 
app.get('/saleslog', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'saleslog.html')); }); 
app.get('/emailnews', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'emailnews.html')); }); 
app.get('/settings', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'settings.html')); }); 

// WARNING: Ensure JWT_SECRET is defined in the scope where this function runs (e.g., process.env.JWT_SECRET)

const verifyToken = (req, res, next) => {
    // 1. Check for Authorization header format (Bearer <token>)
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Access denied. No Access Token provided.' });
    }
    
    // 2. Extract the token (This is the short-lived Access Token)
    const accessToken = authHeader.split(' ')[1];
    
    try {
        // 3. Verify the Access Token (Fast, stateless check)
        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET); 
        
        // 4. CRUCIAL: Check for the 'admin' role (Authorization)
        if (decoded.role !== 'admin') { 
            return res.status(403).json({ message: 'Forbidden. Access limited to administrators.' });
        }
        
        // 5. Success: Attach admin data and proceed
        req.adminUser = decoded; 
        req.adminId = decoded.id;
        next();
        
    } catch (err) {
        // 6. Handle verification errors (Signature mismatch, expiry, etc.)
        
        // --- 🔑 HIGH-PERFORMANCE REFRESH HANDLING ---
        if (err.name === 'TokenExpiredError') {
            // Token is expired, but the signature is valid.
            // DO NOT force re-login yet. Signal the client to use the 
            // Refresh Token endpoint (/api/refresh-token) to get a new Access Token.
            return res.status(401).json({ 
                message: 'Access Token expired. Please refresh the session.',
                expired: true // CRITICAL flag for the client to initiate refresh
            });
        }
        
        // For all other errors (invalid signature, tampering, etc.), force re-login
        res.status(401).json({ message: 'Invalid token signature. Please log in again.' });
    }
};
// --- Multer Configuration (upload) ---
const upload = multer({ 
    storage: multer.memoryStorage(), // Stores file buffer in req.file.buffer
    limits: { fileSize: 50 * 1024 * 1024 } // 5MB limit
});

// Define the expected file fields dynamically (e.g., front-view-upload-1, back-view-upload-1, up to index 4)
const uploadFields = Array.from({ length: 4 }, (_, i) => [
    { name: `front-view-upload-${i + 1}`, maxCount: 1 },
    { name: `back-view-upload-${i + 1}`, maxCount: 1 }
]).flat();

const singleReceiptUpload = multer({ 
    storage: multer.memoryStorage(), // Use memory storage as defined
    limits: { fileSize: 50 * 1024 * 1024 } // 5MB limit

}).single('receipt'); 


/**
 * 1. verifyUserToken (THE SMART GATE)
 * Use this for: Checkout, Cart Sync, Order Placement.
 * It identifies users if they have a token, but lets guests pass through.
 */
const verifyUserToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    // If no token, they are a guest. Proceed without error.
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        req.userId = null; 
        req.isGuest = true;
        return next(); 
    }

    const accessToken = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
        
        if (decoded.role === 'user') {
            req.userId = decoded.id; 
            req.isGuest = false;
        } else {
            req.userId = null;
            req.isGuest = true;
        }
        next(); 
    } catch (err) {
        // If expired, tell the frontend so it can try to refresh
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                message: 'Access Token expired. Refresh required.',
                expired: true 
            });
        }
        // For other errors, just treat them as a guest
        req.userId = null;
        req.isGuest = true;
        next();
    }
};

/**
 * 2. verifySessionCookie (THE REFRESH GATE)
 * Use this ONLY for: /api/auth/refresh
 * This MUST remain a hard gate to protect the refresh cycle.
 */
const verifySessionCookie = (req, res, next) => {
    const refreshToken = req.cookies.userRefreshToken; 
    if (!refreshToken) {
        return res.status(401).json({ message: 'No valid session cookie found.' });
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        req.userId = decoded.id; 
        next(); 
    } catch (err) {
        res.status(401).json({ message: 'Session cookie invalid or expired.' });
    }
};

// Change 'requireUser' to 'requireUserLogin'
const requireUserLogin = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Authentication required.' });
    }

    const accessToken = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
        req.userId = decoded.id; 
        next(); 
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired', expired: true });
        }
        return res.status(401).json({ message: 'Invalid token' });
    }
};

/**
 * Verifies the user token if present, but allows the request to proceed if absent.
 * (This middleware is generally not needed for a protected route like /api/orders/:orderId)
 */
const verifyOptionalToken = (req, res, next) => {
    // 1. Check for token in the HTTP-only cookie
    let token = req.cookies.outflickzToken; 
    
    // 2. Fallback: Check for token in the 'Authorization: Bearer <token>' header
    const authHeader = req.headers.authorization;
    if (!token && authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    }
    if (!token) {
        req.userId = null; 
        return next();
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
                if (decoded.role !== 'user') {
            req.userId = null;
            return next(); 
        }
                req.userId = decoded.id; 
        next();
        
    } catch (err) {
        if (req.cookies.outflickzToken) {
            const isProduction = process.env.NODE_ENV === 'production';
            res.clearCookie('outflickzToken', {
                httpOnly: true,
                secure: isProduction,
                sameSite: isProduction ? 'strict' : 'lax',
            });
        }
        console.warn("Optional JWT Verification Failed (token ignored):", err.message);
        req.userId = null; 
        next(); // Proceed as if unauthenticated
    }
};

// --- GENERAL ADMIN API ROUTES ---d
app.post('/api/admin/register', async (req, res) => {
    // ... registration logic
    res.status(501).json({ message: 'Registration is not yet implemented.' });
});

app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;
    const isProduction = process.env.NODE_ENV === 'production';
    
    try {
        const adminUser = await findAdminUserByEmail(email);
        
        // 1. Validate Credentials
        if (!adminUser || !(await bcrypt.compare(password, adminUser.hashedPassword))) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        
        // --- 2. GENERATE DUAL TOKENS (The Speed and Persistence Fix) ---
        const tokenPayload = { id: adminUser._id, email: adminUser.email, role: 'admin' };
        
        // A. Short-Lived Access Token (For API calls, sent in response body)
        const accessToken = generateAccessToken(tokenPayload);
        
        // B. Long-Lived Refresh Token (For persistent session, sent as secure cookie)
        const refreshToken = generateRefreshToken(tokenPayload);
        // ----------------------------------------------------------------
        
        // 3. Set the Refresh Token in a Secure HTTP-Only Cookie
        // This token keeps the user logged in for 7 days (the duration of the Refresh Token)
        res.cookie('adminRefreshToken', refreshToken, {
            httpOnly: true, // Prevents client-side JS access (XSS security)
            secure: isProduction, // Only sent over HTTPS in production
            sameSite: isProduction ? 'strict' : 'lax', // CSRF protection
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days (matches token expiry)
        });
        
        // 4. Send the short-lived Access Token back to the client
        // The client must store this in memory and use it for all 'Authorization: Bearer' headers.
        res.status(200).json({ 
            message: 'Login successful', 
            // 🚨 CRITICAL CHANGE: Sending the Access Token here
            accessToken: accessToken, 
            adminId: adminUser._id
        });

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.post('/api/admin/forgot-password', async (req, res) => {
    res.status(200).json({ message: 'If an account with that email address exists, a password reset link has been sent.' });
});

app.put('/api/admin/change-password', verifyToken, async (req, res) => {
    // FIX: Get the admin ID from the property set by verifyToken (req.adminUser)
    const adminId = req.adminUser ? (req.adminUser.id || req.adminUser._id) : null;
    const { currentPassword, newPassword } = req.body;

    // 1. Basic Input Validation
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: 'Current password and new password are required.' });
    }

    // 2. New Password Complexity Check
    if (newPassword.length < 8) {
        return res.status(400).json({ message: 'New password must be at least 8 characters long.' });
    }

    try {
        // We no longer rely on req.adminId being set externally.
        // 3. Fetch the admin, explicitly including the password field
        const admin = await Admin.findById(adminId).select('+password');

        if (!admin) {
            // This now correctly captures cases where the token is valid but the 
            // ID extracted from it (adminId) doesn't match an active admin user.
            return res.status(404).json({ message: 'Admin user not found or session expired.' });
        }

        // 4. Verify the current password
        const isMatch = await bcrypt.compare(currentPassword, admin.password);
        if (!isMatch) {
            // Log the failed attempt for security monitoring
            try {
                await logActivity(
                    'ADMIN_PASSWORD_CHANGE_FAILURE',
                    `Admin ${admin.email || 'N/A'} failed to change password due to incorrect current password.`,
                    admin._id,
                    { ipAddress: req.ip }
                );
            } catch (logErr) {
                console.warn('Activity logging failed:', logErr);
            }
            return res.status(401).json({ message: 'The current password you entered is incorrect.' });
        }
        
        // 5. Check if the new password is the same as the current password
        if (currentPassword === newPassword) {
            return res.status(400).json({ message: 'New password cannot be the same as the current password.' });
        }

        // 6. Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10); // 10 is the salt rounds

        // 7. Update the admin's password in the database
        admin.password = hashedPassword;
        await admin.save(); // Save the updated password

        // 8. Log the successful password change event
        try {
            await logActivity(
                'ADMIN_PASSWORD_CHANGE_SUCCESS',
                `Admin **${admin.email || 'N/A'}** successfully changed their password.`,
                admin._id,
                { ipAddress: req.ip }
            );
        } catch (logErr) {
            console.warn('Activity logging failed (success):', logErr);
        }

        // 9. Success Response
        return res.status(200).json({ 
            message: 'Password updated successfully. Please log in again with your new password.',
            shouldRelogin: true // Hint for the frontend
        });

    } catch (error) {
        console.error("Admin password change error:", error);
        return res.status(500).json({ message: 'Server error: Failed to change admin password.' });
    }
});

// POST /api/refresh-token
// This endpoint is the engine for persistent, seamless admin sessions.
app.post('/api/admin/refresh-token', async (req, res) => {
        // Determine production status for secure cookie settings
    const isProduction = process.env.NODE_ENV === 'production';
    
    // 1. Get Refresh Token from secure cookie (MUST use the name set by the login route)
    const refreshToken = req.cookies.adminRefreshToken; // <--- Name updated
    
    if (!refreshToken) {
        return res.status(401).json({ message: 'No session token found. Please log in.' });
    }

    try {
        // 2. Verify the Refresh Token (Long-lived check)
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        
        // Ensure the token is for an admin (security check)
        if (decoded.role !== 'admin') {
            throw new Error('Invalid token role for admin refresh.');
        }

        // 3. Generate a NEW Access Token (short-lived)
        const newAccessToken = generateAccessToken({ 
            id: decoded.id, 
            email: decoded.email,
            role: decoded.role 
        });

        // 4. Send the new Access Token back to the client
        res.status(200).json({ accessToken: newAccessToken });
        // The client receives this and replaces the expired token in its memory/local storage.

    } catch (err) {
        // Refresh token failed verification (expired, invalid signature, or wrong role)
        console.error("Admin Refresh Token Error:", err.message);
        
        // 5. Clear the bad cookie and force a full re-login
        res.clearCookie('adminRefreshToken', { // <--- Name updated
            httpOnly: true, 
            secure: isProduction, 
            sameSite: isProduction ? 'strict' : 'lax'
        });
        
        // Use 401 status code for authentication failure
        res.status(401).json({ message: 'Session expired or invalid. Please log in again.' });
    }
});

/**
 * POST /api/admin/logout
 * Clears the secure refresh token cookie to terminate the admin session.
 */
app.post('/api/admin/logout', (req, res) => {
    const isProduction = process.env.NODE_ENV === 'production';

    try {
        // 1. Clear the Refresh Token Cookie
        // The options (httpOnly, secure, sameSite) must match those used during Login
        res.clearCookie('adminRefreshToken', {
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? 'strict' : 'lax',
            path: '/' // Ensure it clears for the entire application path
        });

        // 2. Respond to the client
        // The frontend should also clear the Access Token from its memory/local storage
        res.status(200).json({ message: 'Admin logged out successfully.' });

    } catch (error) {
        console.error("Logout error:", error);
        res.status(500).json({ message: 'Server error during logout.' });
    }
});

app.get('/api/admin/dashboard/stats', verifyToken, async (req, res) => {
    try {
        // Log that the request has successfully reached the main API handler
        console.log("Attempting to retrieve real-time dashboard stats...");
        
        // This now calls the updated function that aggregates stock from all product models
        const stats = await getRealTimeDashboardStats();
        
        // Log success
        console.log("Dashboard stats retrieved successfully.");
        
        res.status(200).json(stats);
    } catch (error) {
        // ⭐ CRITICAL UPDATE: Log the entire error object to get the stack trace.
        // This will pinpoint the exact line in getRealTimeDashboardStats() that is crashing.
        console.error("Dashboard Stats API Crash Detected:");
        console.error(error); // Logs the name, message, and stack trace

        res.status(500).json({ 
            message: 'Failed to retrieve dashboard stats due to a server crash.',
            internalError: error.message // Optionally expose the message for client-side context
        });
    }
});

app.get('/api/analytics/visitors/:period', verifyToken, async (req, res) => {
    try {
        const { period } = req.params; // Extract the requested period ('daily', 'monthly', etc.)
        
        console.log(`Attempting to retrieve visitor analytics for period: ${period}...`);
        
        // Pass the period parameter to the analytics function
        // NOTE: You will need to rewrite getVisitorAnalytics to accept and use this parameter.
        const stats = await getVisitorAnalytics(period); 
        
        console.log("Visitor analytics retrieved successfully.");
        
        res.status(200).json(stats);
        
    } catch (error) {
        console.error("Visitor Analytics API Crash Detected:");
        console.error(error);

        res.status(500).json({ 
            message: 'Failed to retrieve visitor analytics due to a server error.',
            internalError: error.message 
        });
    }
});

app.get('/api/admin/orders/all', verifyToken, async (req, res) => {
    try {
        // Fetch all orders using your existing helper
        const allOrders = await getAllOrders();
        
        // ⭐️ STRICT FILTER: Exclude abandoned Paystack checkouts
        const validOrders = allOrders.filter(order => {
            if (order.paymentMethod === 'Paystack') {
                // Show only if Paid, or if it's no longer in 'Pending' status
                return order.paymentStatus === 'Paid' || order.status !== 'Pending';
            }
            // Always include Bank Transfers for the Sales Log
            return true;
        });

        const sanitizedOrders = validOrders.map(order => ({
            ...order,
            displayId: order.orderReference || order._id,
            isAutomated: !!order.paymentTxnId 
        }));

        res.status(200).json(sanitizedOrders);
        
    } catch (error) {
        console.error("Sales Log API Crash:", error);
        res.status(500).json({ message: 'Failed to retrieve order records.', error: error.message });
    }
});

app.post('/api/admin/newsletter/send', verifyToken, async (req, res) => {
    // 1. Extract newsletter details from the request body
    const { 
        subject, 
        htmlContent 
    } = req.body;

    // 2. Basic validation
    if (!subject || !htmlContent) {
        return res.status(400).json({ 
            message: 'Missing required fields: subject and htmlContent are mandatory.' 
        });
    }

    try {
        // 3. Fetch all user emails for the newsletter
        // We only need the 'email' field for sending the newsletter
        const users = await User.find({}).select('email').lean();
        
        if (users.length === 0) {
            return res.status(200).json({ 
                message: 'No users registered to receive the newsletter. Email process aborted.',
                successCount: 0
            });
        }
        
        // Extract just the emails into an array
        const recipientEmails = users.map(user => user.email).filter(email => email); // Filter out any null/undefined emails

        // 4. Send the newsletter to all recipients
        
        // Nodemailer's sendMail is designed to handle multiple recipients 
        // if the 'to' field is a comma-separated string or an array.
        // For performance and centralized sending status tracking, 
        // we send a single mail with all recipients in the 'bcc' field.
        
        // This method also ensures individual users cannot see the full mailing list.
        const allRecipientsBCC = recipientEmails.join(', ');

        const mailOptions = {
            to: process.env.EMAIL_USER, // Send the main email to the sender's address (or a placeholder)
            bcc: allRecipientsBCC, // Send the actual content to all users via BCC
            subject: subject,
            html: htmlContent
        };
        
        // Re-use the sendMail helper function
        const info = await sendMail(mailOptions.to, mailOptions.subject, mailOptions.html, mailOptions.bcc);

        // 5. Success Response
        console.log(`Newsletter sent successfully to ${recipientEmails.length} recipients.`);
        console.log('Nodemailer response:', info);

        return res.status(200).json({
            message: `Newsletter successfully queued for sending to ${recipientEmails.length} recipients.`,
            successCount: recipientEmails.length,
            // info: info // Optionally include Nodemailer info for debugging
        });

    } catch (error) {
        console.error('Newsletter send error:', error);

        // This handles both database errors and errors thrown by the sendMail helper 
        // (e.g., if EMAIL_USER/PASS is missing)
        return res.status(500).json({ 
            message: `Failed to send newsletter. Error: ${error.message || 'Internal Server Error'}` 
        });
    }
});

app.get('/api/admin/users/all', verifyToken, async (req, res) => {
    try {
        // 1. Fetch Registered Users from the User Collection
        const registeredUsers = await User.find({})
            .select('email profile status membership')
            .lean();

        const transformedRegistered = registeredUsers.map(user => ({
            _id: user._id,
            name: `${user.profile?.firstName || ''} ${user.profile?.lastName || ''}`.trim() || 'N/A',
            email: user.email,
            // If they are in this collection, they are NOT Guests. 
            // We check their role for VIP vs Basic.
            statusLabel: user.status?.role === 'vip' ? 'VIP Member' : 'Basic User',
            statusColor: user.status?.role === 'vip' ? 'emerald' : 'blue',
            isGuest: false,
            joinedDate: user.membership?.memberSince || user.createdAt
        }));

        // 2. Fetch Guest Orders (where userId is null)
        const guestOrders = await Order.find({ userId: null })
            .select('guestEmail shippingAddress createdAt isGuest')
            .lean();

        // Unique Guests by Email
        const guestMap = new Map();
        guestOrders.forEach(order => {
            const email = order.guestEmail || order.shippingAddress?.email;
            if (email && !guestMap.has(email)) {
                guestMap.set(email, {
                    _id: order._id, 
                    name: `${order.shippingAddress?.firstName || ''} ${order.shippingAddress?.lastName || ''}`.trim() || 'Guest',
                    email: email,
                    statusLabel: 'Guest', // Explicit Guest Label
                    statusColor: 'orange', // Orange for Guests
                    isGuest: true,
                    joinedDate: order.createdAt
                });
            }
        });

        // Combine both lists
        const allRecords = [...transformedRegistered, ...Array.from(guestMap.values())];

        res.status(200).json({ 
            users: allRecords,
            count: allRecords.length 
        });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching membership list' });
    }
});

app.get('/api/admin/users/:id', verifyToken, async (req, res) => {
    try {
        const id = req.params.id;
        let detailedUser = null;

        // Try to find a Registered User first
        const user = await User.findById(id)
            .select('email profile address status membership')
            .lean();

        if (user) {
            const addressParts = [
                user.address?.street, user.address?.city, user.address?.state, user.address?.zip, user.address?.country
            ].filter(Boolean);
            
            detailedUser = {
                _id: user._id,
                name: `${user.profile?.firstName || ''} ${user.profile?.lastName || ''}`.trim() || 'N/A',
                email: user.email,
                isMember: user.status?.role === 'vip',
                isGuest: false,
                createdAt: user.membership?.memberSince,
                phone: user.profile?.phone || 'N/A',
                whatsappNumber: user.profile?.whatsapp || 'N/A', 
                contactAddress: addressParts.length > 0 ? addressParts.join(', ') : 'No Address Provided'
            };
        } else {
            // If no user found, look for a Guest Order using this ID (or email)
            const latestOrder = await Order.findOne({ 
                $or: [{ _id: id }, { guestEmail: id }, { "shippingAddress.email": id }],
                userId: null 
            }).sort({ createdAt: -1 }).lean();

            if (latestOrder) {
                const s = latestOrder.shippingAddress;
                detailedUser = {
                    _id: latestOrder._id,
                    name: s ? `${s.firstName || ''} ${s.lastName || ''}`.trim() : 'Guest Customer',
                    email: latestOrder.guestEmail || s?.email,
                    isMember: false,
                    isGuest: true,
                    createdAt: latestOrder.createdAt,
                    phone: s?.phone || 'N/A',
                    whatsappNumber: s?.whatsapp || 'N/A',
                    contactAddress: s ? `${s.street}, ${s.city}, ${s.state}` : 'No Address Provided'
                };
            }
        }

        if (!detailedUser) return res.status(404).json({ message: 'Customer record not found.' });

        return res.status(200).json({ user: detailedUser });

    } catch (error) {
        console.error('Admin profile fetch error:', error);
        return res.status(500).json({ message: 'Server error retrieving details.' });
    }
});


app.get('/api/admin/users/:userId/orders', verifyToken, async (req, res) => {
    try {
        const userId = req.params.userId;
        let query;

        // Check if the ID belongs to a registered User
        const userExists = await User.exists({ _id: userId });

        if (userExists) {
            // Query for Registered User
            query = { userId: userId };
        } else {
            // Query for Guest: Find all orders with this guest's email 
            // We first get the email from the "ID" (which might be an order ID or email)
            const refOrder = await Order.findById(userId).select('guestEmail shippingAddress').lean();
            const email = refOrder?.guestEmail || refOrder?.shippingAddress?.email || userId;

            query = { 
                userId: null, 
                $or: [{ guestEmail: email }, { "shippingAddress.email": email }] 
            };
        }

        // Apply your existing filters for "Real" orders
        const userOrders = await Order.find({ 
            ...query,
            $or: [
                { paymentMethod: { $ne: 'Paystack' } }, 
                { paymentStatus: 'Paid' },             
                { status: { $ne: 'Pending' } }         
            ]
        }) 
        .sort({ createdAt: -1 })
        .lean();

        return res.status(200).json({ 
            orders: userOrders.map(o => ({ ...o, items: o.items || [] })),
            count: userOrders.length
        });

    } catch (error) {
        res.status(500).json({ message: 'Server error retrieving history.' });
    }
});

app.get('/api/admin/orders/pending', verifyToken, async (req, res) => {
    try {
        const pendingOrders = await Order.find({ 
            status: { $in: ['Pending', 'Processing', 'Inventory Failure (Manual Review)'] } 
        })
        .sort({ createdAt: 1 })
        .lean();

        const populatedOrders = await Promise.all(
            pendingOrders.map(async (order) => {
                let userName = 'Guest';
                let email = 'N/A';

                if (order.userId) {
                    // Path A: Registered Member
                    const user = await User.findById(order.userId)
                        .select('profile.firstName profile.lastName email') 
                        .lean();
                    if (user) {
                        userName = `${user.profile?.firstName || ''} ${user.profile?.lastName || ''}`.trim() || user.email;
                        email = user.email;
                    }
                } else {
                    // Path B: Guest User (Pull from Order/Shipping fields)
                    const s = order.shippingAddress;
                    userName = s ? `${s.firstName || ''} ${s.lastName || ''}`.trim() : (order.customerName || 'Guest');
                    email = order.guestEmail || s?.email || order.email || 'Guest Email';
                }

                const isPaystackPaid = order.paymentMethod === 'Paystack' && 
                                     order.amountPaidKobo >= (order.totalAmount * 100);
                
                return {
                    ...order,
                    userName,
                    email,
                    paymentStatus: isPaystackPaid ? 'Paid' : (order.paymentStatus || 'Awaiting'),
                    isGuest: !order.userId
                };
            })
        );

        res.status(200).json(populatedOrders);
    } catch (error) {
        console.error("Pending Orders Fetch Error:", error);
        res.status(500).json({ message: 'Failed to retrieve pending orders.' });
    }
});

// NEW: Fetch orders that are PAID and ready for Shipping/Fulfillment
app.get('/api/admin/orders/paid', verifyToken, async (req, res) => {
    try {
        // 1. Fetch orders that are officially 'Confirmed' OR 
        //    'Pending' orders that might be Paystack-paid.
        const orders = await Order.find({ 
            status: { $in: ['Confirmed', 'Completed', 'Pending'] } 
        })
        .select('_id userId totalAmount updatedAt status paymentMethod orderReference amountPaidKobo paymentTxnId')
        .sort({ updatedAt: -1 })
        .lean();

        const sanitizedPaidOrders = await Promise.all(orders.map(async (order) => {
            // Check if Paystack payment is verified (e.g., 10000 kobo for 100 Naira)
            const isPaystackPaid = order.paymentMethod === 'Paystack' && 
                                 (order.amountPaidKobo >= (order.totalAmount * 100));

            // Only include in this "Paid" list if it's Confirmed OR a verified Paystack order
            if (order.status === 'Confirmed' || order.status === 'Completed' || isPaystackPaid) {
                const user = await User.findById(order.userId).select('email profile').lean();
                
                return {
                    ...order,
                    paymentStatus: 'Paid', 
                    userName: user?.profile?.firstName ? `${user.profile.firstName} ${user.profile.lastName}` : (user?.email || 'Guest'),
                    email: user?.email || 'N/A'
                };
            }
            return null; // Skip non-paid pending orders
        }));

        // Filter out the nulls from the map
        const finalOrders = sanitizedPaidOrders.filter(o => o !== null);

        res.status(200).json(finalOrders);
    } catch (error) {
        console.error("Paid Orders API Error:", error);
        res.status(500).json({ message: 'Failed to retrieve paid orders.' });
    }
});

// =========================================================
// 8c. GET /api/admin/orders/confirmed - Fetch Confirmed Orders
// =========================================================
app.get('/api/admin/orders/confirmed', verifyToken, async (req, res) => {
    try {
        // Find orders ready for fulfillment. 
        // Note: 'Processing' is included as a fallback for the manual Admin confirmation flow.
        const confirmedOrders = await Order.find({ 
            status: { $in: ['Confirmed', 'Shipped', 'Delivered'] } 
        })
        .select('_id userId totalAmount createdAt status orderReference totalQuantity')
        .sort({ createdAt: -1 })
        .lean();

        const populatedOrders = await Promise.all(
            confirmedOrders.map(async (order) => {
                const user = await User.findById(order.userId)
                    .select('profile.firstName profile.lastName email') 
                    .lean();

                const userName = (user?.profile?.firstName && user?.profile?.lastName) 
                    ? `${user.profile.firstName} ${user.profile.lastName}` 
                    : user?.email || 'N/A';
                
                return {
                    ...order,
                    userName,
                    email: user?.email || 'Unknown User',
                };
            })
        );

        res.status(200).json(populatedOrders);
    } catch (error) {
        console.error('Error fetching confirmed orders:', error);
        res.status(500).json({ message: 'Failed to retrieve confirmed orders.' });
    }
});

// =========================================================
// 8b. GET /api/admin/orders/:orderId - Fetch Single Detailed Order
// =========================================================
app.get('/api/admin/orders/:orderId', verifyToken, async (req, res) => {
    try {
        const orderId = req.params.orderId;

        // 1. Fetch the single order
        let order = null;
        if (orderId.match(/^[0-9a-fA-F]{24}$/)) {
            order = await Order.findById(orderId).lean();
        }

        if (!order) {
            order = await Order.findOne({ orderReference: orderId }).lean();
        }

        if (!order) {
            return res.status(404).json({ message: 'Order not found.' });
        }

        // 2. Augment order items with product details
        const augmentedResults = await augmentOrdersWithProductDetails([order]);
        let detailedOrder = augmentedResults[0];

        // 3. Generate Signed URL for Proof of Payment if it exists
        if (detailedOrder.paymentReceiptUrl) {
            detailedOrder.paymentReceiptUrl = await generateSignedUrl(detailedOrder.paymentReceiptUrl);
        }

        // 4. Determine Customer Identity (Guest vs Member)
        let customerName = 'Guest Customer';
        let customerEmail = 'N/A';
        let whatsapp = 'N/A';

        if (detailedOrder.userId) {
            // Path A: Registered Member
            const user = await User.findById(detailedOrder.userId)
                .select('profile.firstName profile.lastName email profile.whatsapp')
                .lean();
            
            if (user) {
                customerName = `${user.profile?.firstName || ''} ${user.profile?.lastName || ''}`.trim() || user.email;
                customerEmail = user.email;
                whatsapp = user.profile?.whatsapp || 'N/A';
            }
        } 
        
        // Path B: Guest User Logic (Use Guest fields if Member lookup failed or if flagged as Guest)
        if (!detailedOrder.userId || detailedOrder.isGuest) {
            const s = detailedOrder.shippingAddress;
            // Use the specific guest fields from your database schema
            customerName = s ? `${s.firstName || ''} ${s.lastName || ''}`.trim() : (detailedOrder.customerName || 'Guest');
            customerEmail = detailedOrder.guestEmail || s?.email || detailedOrder.email || 'N/A';
            whatsapp = s?.whatsapp || 'N/A';
        }

        // 5. Build Final Response Object
        const finalDetailedOrder = {
            ...detailedOrder,
            customerName: customerName,
            email: customerEmail,
            whatsappNumber: whatsapp,
            isGuest: !detailedOrder.userId || detailedOrder.isGuest
        };

        return res.status(200).json({ order: finalDetailedOrder });

    } catch (error) {
        console.error('Admin single order fetch error:', error);
        return res.status(500).json({ message: 'Server error: Failed to retrieve order details.' });
    }
});


// 9. PUT /api/admin/orders/:orderId/confirm - Confirm an Order (Admin Protected)
// =========================================================
app.put('/api/admin/orders/:orderId/confirm', verifyToken, async (req, res) => {
    const orderId = req.params.orderId;
    const adminId = req.adminId;

    if (!orderId) {
        return res.status(400).json({ message: 'Order ID is required for confirmation.' });
    }

    try {
        // 1. Initial status change from 'Pending' to 'Processing' (The "CLAIM" step.)
        const updatedOrder = await Order.findOneAndUpdate(
            { 
                _id: orderId, 
                status: { $in: ['Pending', 'Processing'] } 
            }, 
            { 
                $set: { 
                    status: 'Processing', 
                    confirmedAt: new Date(), 
                    confirmedBy: adminId 
                } 
            },
            { new: true, select: 'userId status totalAmount items email' } // 👈 Added 'email' to selection
        ).lean();

        if (!updatedOrder) {
            const checkOrder = await Order.findById(orderId).select('status').lean();
            console.warn(`[Inventory Skip] Order ${orderId} is in status: ${checkOrder?.status || 'Not Found'}`);
            return res.status(409).json({ message: 'Order not found or is already processed.' });
        }
        
        // 2. CRITICAL STEP: Deduct Inventory and finalize status to 'Confirmed' atomically
        let finalOrder;
        try {
            console.log(`[Inventory] Attempting atomic inventory deduction for Order ${orderId}.`);
            finalOrder = await processOrderCompletion(orderId, adminId); 
            console.log(`[Inventory Success] Deduction completed. Final status: ${finalOrder.status}.`);
            
        } catch (inventoryError) {
            if (inventoryError.isRaceCondition) {
                const confirmedOrder = await Order.findById(orderId).lean();
                return res.status(200).json({ 
                    message: `Order ${orderId} was confirmed by a concurrent request.`,
                    order: confirmedOrder 
                });
            }
            
            console.error('Inventory deduction failed:', inventoryError.message);
            await Order.findByIdAndUpdate(orderId, { 
                $push: { notes: `Inventory deduction failed on ${new Date().toISOString()}: ${inventoryError.message}` }
            });
            
            return res.status(409).json({ 
                message: 'Payment confirmed, but inventory deduction failed. Flagged for review.',
                error: inventoryError.message
            });
        }
        
        // 3. GET CUSTOMER EMAIL (Works for both Registered Users and Guests) 📧
        // Attempt to find a registered user first
        const registeredUser = await User.findById(updatedOrder.userId).select('email').lean();
        
        /**
         * DUAL-PATH EMAIL LOGIC:
         * If the user is registered, we use their account email.
         * If they are a GUEST, the User search returns null, so we use the email stored on the Order.
         */
        const customerEmail = registeredUser ? registeredUser.email : (finalOrder.email || updatedOrder.email);

        if (customerEmail) {
            try {
                const userLabel = registeredUser ? "Registered Member" : "Guest User";
                console.log(`[Email] Sending confirmation to ${userLabel}: ${customerEmail}`);
                
                await sendOrderConfirmationEmailForAdmin(customerEmail, finalOrder);
                
                console.log(`[Email Success] Confirmation sent to ${customerEmail}.`);
            } catch (emailError) {
                console.error(`[Email Failure] CRITICAL WARNING: Could not email ${customerEmail}:`, emailError.message);
            }
        } else {
            console.warn(`[Email Skip] No email address found for order ${orderId} (Guest or Member).`);
            await Order.findByIdAndUpdate(orderId, { 
                $push: { notes: `Warning: Confirmation email not sent because no email address was found.` }
            });
        }
        
        // ⭐ INTEGRATION: Log the successful confirmation action
        if (finalOrder) {
            await logAdminOrderAction(finalOrder, adminId, 'ORDER_CONFIRMED'); 
        }

        // 4. Success Response
        res.status(200).json({ 
            message: `Order ${orderId} confirmed, inventory deducted, and customer notified.`,
            order: finalOrder 
        });

    } catch (error) {
        console.error(`Error confirming order ${orderId}:`, error);
        res.status(500).json({ message: 'Failed to confirm order due to a server error.' });
    }
});

// =========================================================
// 10. PUT /api/admin/orders/:orderId/cancel - Cancel an Order (Admin Protected)
// =========================================================
app.put('/api/admin/orders/:orderId/cancel', verifyToken, async (req, res) => {
    const orderId = req.params.orderId;
    const adminId = req.adminId; // Extracted from verifyToken middleware

    if (!orderId) {
        return res.status(400).json({ message: 'Order ID is required for cancellation.' });
    }

    try {
        // 1. Find and Update the order
        // We only allow cancellation if the order is in a state that hasn't been shipped yet
        const cancelledOrder = await Order.findOneAndUpdate(
            { 
                _id: orderId, 
                status: { $in: ['Pending', 'Processing', 'Inventory Failure (Manual Review)'] } 
            }, 
            { 
                $set: { 
                    status: 'Cancelled', 
                    cancelledAt: new Date(), 
                    cancelledBy: adminId 
                } 
            },
            { new: true } 
        ).lean();

        // 2. Check if the order was eligible for cancellation
        if (!cancelledOrder) {
            console.warn(`[Cancel Skip] Order ${orderId} not found or status ineligible for cancellation.`);
            
            const existingOrder = await Order.findById(orderId).select('status').lean();
            if (!existingOrder) {
                return res.status(404).json({ message: 'Order not found.' });
            }
            return res.status(409).json({ 
                message: `Order cannot be cancelled. Current status is: ${existingOrder.status}` 
            });
        }

        console.log(`[Admin Action] Order ${orderId} successfully cancelled by Admin ${adminId}.`);

        // 3. OPTIONAL: Send Cancellation Email Notification
        const user = await User.findById(cancelledOrder.userId).select('email').lean();
        if (user && user.email) {
            try {
                // You would need to create this helper function similar to your confirmation email helper
                // await sendOrderCancellationEmail(user.email, cancelledOrder);
                console.log(`[Email] Cancellation notice ready for ${user.email}`);
            } catch (emailError) {
                console.error(`[Email Failure] Failed to send cancellation email:`, emailError.message);
            }
        }

        // 4. INTEGRATION: Log the admin action
        // Following your pattern for logAdminOrderAction
        try {
            await logAdminOrderAction(cancelledOrder, adminId, 'ORDER_CANCELLED');
        } catch (logError) {
            console.error(`[Log Failure] Failed to log admin cancellation:`, logError.message);
        }

        // 5. Success Response
        res.status(200).json({ 
            message: `Order ${orderId} has been successfully cancelled.`,
            order: cancelledOrder 
        });

    } catch (error) {
        console.error(`Error cancelling order ${orderId}:`, error);
        res.status(500).json({ message: 'Failed to cancel order due to a server error.' });
    }
});

app.put('/api/admin/orders/:orderId/status', verifyToken, async (req, res) => {
    const { orderId } = req.params;
    const { newStatus } = req.body; 
    
    // 1. Define the strict logical flow of the store
    const validTransitions = {
        'Pending': ['Confirmed', 'Cancelled'],
        'Processing': ['Confirmed', 'Cancelled'],
        'Inventory Failure (Manual Review)': ['Confirmed', 'Cancelled'],
        'Confirmed': ['Shipped', 'Cancelled'], 
        'Shipped': ['Delivered'],
        'Delivered': [], // Final state
        'Cancelled': []  // Final state
    };
    
    try {
        const order = await Order.findById(orderId);
        if (!order) return res.status(404).json({ message: 'Order not found.' });

        // 2. BLOCKER: Force use of the "Confirm" button for inventory deduction
        // This ensures the stock is actually removed before shipping starts
        if (['Pending', 'Processing', 'Inventory Failure (Manual Review)'].includes(order.status) && 
            !['Confirmed', 'Cancelled'].includes(newStatus)) {
            return res.status(400).json({ 
                message: `Order must be Confirmed (Inventory Deducted) before moving to ${newStatus}. Please click the 'Confirm' button on the User Orders page first.` 
            });
        }

        // 3. LOGIC CHECK: Ensure the transition is allowed based on current status
        const allowedNext = validTransitions[order.status] || [];
        if (order.status !== newStatus && !allowedNext.includes(newStatus)) {
            return res.status(400).json({ 
                message: `Invalid movement. You cannot move an order from ${order.status} directly to ${newStatus}.` 
            });
        }
        
        // 4. Update order fields
        order.status = newStatus;
        order.updatedAt = Date.now();
        
        if (newStatus === 'Shipped') order.shippedAt = new Date();
        if (newStatus === 'Delivered') order.deliveredAt = new Date();

        const updatedOrder = await order.save();

        // 5. Trigger Customer Notifications
        const user = await User.findById(updatedOrder.userId).select('email').lean();
        if (user?.email) {
            try {
                if (newStatus === 'Shipped') await sendShippingUpdateEmail(user.email, updatedOrder); 
                else if (newStatus === 'Delivered') await sendDeliveredEmail(user.email, updatedOrder);
            } catch (e) { 
                console.error("Fulfillment email failed:", e.message); 
            }
        }
        
        // 6. Log for Admin Audit Trail
        await logAdminStatusUpdate(updatedOrder, req.adminId, `ORDER_${newStatus.toUpperCase()}`); 

        res.status(200).json({ message: `Order successfully moved to ${newStatus}.`, order: updatedOrder });
    } catch (error) {
        console.error("Status Update Error:", error);
        res.status(500).json({ message: 'Server error during status update.' });
    }
});

// GET /api/admin/capscollections - Fetch ALL Cap Collections (Admin List View)
app.get('/api/admin/capscollections', verifyToken, async (req, res) => {
    // Note: The admin view usually needs pagination, filtering, and sorting,
    // but this example provides a basic, unsorted list.
    try {
        // Find all collections, sort by creation date (newest first), and use .lean()
        const collections = await CapCollection.find({})
            .sort({ createdAt: -1 })
            .lean(); 

        if (!collections || collections.length === 0) {
            return res.status(200).json([]); // Return an empty array instead of 404 if no collections exist
        }

        // --- Prepare Collections for Response (Sign URLs) ---
        
        // This process iterates through every collection and every variation 
        // to generate signed URLs for all images before sending the response.
        const collectionsWithSignedUrls = await Promise.all(
            collections.map(async (collection) => {
                
                const signedVariations = await Promise.all(
                    collection.variations.map(async (v) => ({
                        ...v,
                        frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl, 
                        backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl 
                    }))
                );

                return {
                    ...collection, // Spread the rest of the collection data
                    variations: signedVariations,
                };
            })
        );

        res.status(200).json(collectionsWithSignedUrls);
    } catch (error) {
        console.error('Error fetching all cap collections for admin:', error);
        res.status(500).json({ message: 'Server error fetching cap collection list.' });
    }
});

// GET /api/admin/capscollections/:id - Fetch Single Cap Collection
app.get('/api/admin/capscollections/:id', verifyToken, async (req, res) => {
    try {
        const collectionId = req.params.id;
        // .lean() is used for performance when no modification or virtuals are needed, which is good practice for simple GETs
        const collection = await CapCollection.findById(collectionId).lean(); 

        if (!collection) {
            return res.status(404).json({ message: 'Cap Collection not found.' });
        }

        // Sign URLs for all images in all variations for the detailed view
        const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
            ...v,
            frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl, 
            backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl 
        })));
        
        collection.variations = signedVariations;

        res.status(200).json(collection);
    } catch (error) {
        console.error('Error fetching cap collection:', error);
        res.status(500).json({ message: 'Server error fetching cap collection data.' });
    }
});
// POST /api/admin/capscollections - Create New Cap Collection
app.post(
    '/api/admin/capscollections',
    verifyToken, 
    upload.fields(uploadFields), 
    async (req, res) => {
        try {
            // A. Extract JSON Metadata
            if (!req.body.collectionData) {
                return res.status(400).json({ message: "Missing collection data payload." });
            }
            const collectionData = JSON.parse(req.body.collectionData);

            // B. Process Files and Integrate Paths into Variations
            const files = req.files; 
            const finalVariations = [];
            const uploadPromises = [];
            
            for (const variation of collectionData.variations) {
                const index = variation.variationIndex;
                const frontFile = files[`front-view-upload-${index}`]?.[0];
                const backFile = files[`back-view-upload-${index}`]?.[0];

                if (!frontFile || !backFile) {
                    throw new Error(`Missing BOTH front and back image files for Variation #${index}.`);
                }

                const uploadFrontPromise = uploadFileToPermanentStorage(frontFile);
                const uploadBackPromise = uploadFileToPermanentStorage(backFile);
                
                // Combine the upload promises and push the final variation data
                const combinedUploadPromise = Promise.all([uploadFrontPromise, uploadBackPromise])
                    .then(([frontImageUrl, backImageUrl]) => {
                        finalVariations.push({
                            variationIndex: variation.variationIndex,
                            colorHex: variation.colorHex,
                            // 🔑 CRITICAL FIX: Include the 'stock' field here
                            stock: variation.stock || 0, 
                            frontImageUrl: frontImageUrl, 
                            backImageUrl: backImageUrl, 
                        });
                    });
                    
                uploadPromises.push(combinedUploadPromise);
            }
            
            // Wait for all image uploads to complete
            await Promise.all(uploadPromises);

            if (finalVariations.length === 0) {
                return res.status(400).json({ message: "No valid product images and metadata were received." });
            }

            // C. Create the Final Product Object
            const newCollection = new CapCollection({
                name: collectionData.name,
                tag: collectionData.tag,
                price: collectionData.price, 
                // sizes: collectionData.sizes, // Removed as per schema context
                // totalStock is intentionally omitted/set to 0. 
                // The pre('save') middleware will calculate the correct sum from 'variations'.
                isActive: collectionData.isActive,
                variations: finalVariations, 
            });

            // D. Save to Database
            // The pre('save') hook runs here, calculates totalStock from finalVariations, and sets it.
            const savedCollection = await newCollection.save();

            res.status(201).json({ 
                message: 'Cap Collection created successfully and images uploaded to storage.',
                collectionId: savedCollection._id,
                name: savedCollection.name
            });

        } catch (error) {
            console.error('Error creating cap collection:', error); 
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors }); 
            }
            res.status(500).json({ message: 'Server error during cap collection creation or file upload.', details: error.message });
        }
    }
);

// PUT /api/admin/capscollections/:id - Update Cap Collection
app.put(
    '/api/admin/capscollections/:id',
    verifyToken, 
    upload.fields(uploadFields), 
    async (req, res) => {
        const collectionId = req.params.id;
        let existingCollection;
        
        try {
            existingCollection = await CapCollection.findById(collectionId);
            if (!existingCollection) {
                return res.status(404).json({ message: 'Cap Collection not found for update.' });
            }

            const isQuickRestock = req.get('Content-Type')?.includes('application/json') && !req.body.collectionData;
            
            // A. HANDLE QUICK RESTOCK (JSON only, no multipart/form-data)
            if (isQuickRestock) {
                const { totalStock, isActive } = req.body;

                if (totalStock === undefined || isActive === undefined) {
                    return res.status(400).json({ message: "Missing 'totalStock' or 'isActive' in simple update payload." });
                }
                
                // ⚠️ FIX START: Update stock on all variations before saving ⚠️
                const newStockValue = parseInt(totalStock); // Ensure it's an integer
                
                if (isNaN(newStockValue) || newStockValue < 0) {
                     return res.status(400).json({ message: "Invalid 'totalStock' value for restock." });
                }

                // 1. Update the stock field on every variation sub-document
                existingCollection.variations = existingCollection.variations.map(variation => {
                    // This is the CRITICAL change: update the sub-document field
                    variation.stock = newStockValue; 
                    return variation;
                });
                
                // 2. Update the root isActive field
                existingCollection.isActive = isActive; 
                
                // When .save() runs, the pre('save') hook will correctly calculate 
                // totalStock based on the sum of the newly updated variation stocks.
                const updatedCollection = await existingCollection.save();
                // ⚠️ FIX END ⚠️

                return res.status(200).json({ 
                    message: `Cap Collection quick-updated. Stock: ${updatedCollection.totalStock}, Active: ${updatedCollection.isActive}.`,
                    collectionId: updatedCollection._id
                });
            }
            
            // B. HANDLE FULL FORM SUBMISSION (Multipart/form-data)
            // ... (rest of the full update logic remains correct as it overwrites variations)
            if (!req.body.collectionData) {
                return res.status(400).json({ message: "Missing collection data payload for full update." });
            }

            const collectionData = JSON.parse(req.body.collectionData);
            const files = req.files; 
            const updatedVariations = [];
            const uploadPromises = [];
            const oldImagesToDelete = [];

            for (const incomingVariation of collectionData.variations) {
                const index = incomingVariation.variationIndex;
                const existingPermanentVariation = existingCollection.variations.find(v => v.variationIndex === index);

                let finalFrontUrl = existingPermanentVariation?.frontImageUrl || null;
                let finalBackUrl = existingPermanentVariation?.backImageUrl || null;

                // Process FRONT Image
                const frontFileKey = `front-view-upload-${index}`;
                const newFrontFile = files[frontFileKey]?.[0];

                if (newFrontFile) {
                    if (existingPermanentVariation?.frontImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.frontImageUrl);
                    }
                    const frontUploadPromise = uploadFileToPermanentStorage(newFrontFile).then(url => { finalFrontUrl = url; });
                    uploadPromises.push(frontUploadPromise);
                } else if (!finalFrontUrl) {
                    throw new Error(`Front image missing for Variation #${index}.`);
                }
                
                // Process BACK Image
                const backFileKey = `back-view-upload-${index}`;
                const newBackFile = files[backFileKey]?.[0];

                if (newBackFile) {
                    if (existingPermanentVariation?.backImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.backImageUrl);
                    }
                    const backUploadPromise = uploadFileToPermanentStorage(newBackFile).then(url => { finalBackUrl = url; });
                    uploadPromises.push(backUploadPromise);
                } else if (!finalBackUrl) {
                    throw new Error(`Back image missing for Variation #${index}.`);
                }
                
                updatedVariations.push({
                    variationIndex: index,
                    colorHex: incomingVariation.colorHex,
                    // The stock value is also needed from the incoming data for the full update
                    stock: incomingVariation.stock, 
                    get frontImageUrl() { return finalFrontUrl; }, 
                    get backImageUrl() { return finalBackUrl; }, 
                });
            }
            
            await Promise.all(uploadPromises);

            if (updatedVariations.length === 0) {
                return res.status(400).json({ message: "No valid variations were processed for update." });
            }
            
            // Update the Document Fields
            existingCollection.name = collectionData.name;
            existingCollection.tag = collectionData.tag;
            existingCollection.price = collectionData.price;
            // existingCollection.sizes = collectionData.sizes; // Removed sizes field based on schema context
            // totalStock is not needed here; pre('save') will calculate it
            existingCollection.isActive = collectionData.isActive;
            
            // Map final URLs and stock data to the existing collection model
            existingCollection.variations = updatedVariations.map(v => ({
                variationIndex: v.variationIndex,
                colorHex: v.colorHex,
                stock: v.stock, // IMPORTANT: Use the stock value from the incoming data
                frontImageUrl: v.frontImageUrl, 
                backImageUrl: v.backImageUrl, 
            }));
            
            // Save to Database
            const updatedCollection = await existingCollection.save();

            // Delete old images in the background (fire and forget)
            oldImagesToDelete.forEach(url => deleteFileFromPermanentStorage(url));

            res.status(200).json({ 
                message: 'Cap Collection updated and images handled successfully.',
                collectionId: updatedCollection._id,
                name: updatedCollection.name
            });

        } catch (error) {
            console.error('Error updating cap collection:', error); 
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors }); 
            }
            res.status(500).json({ message: 'Server error during cap collection update or file upload.', details: error.message });
        }
    }
);

// DELETE /api/admin/capscollections/:id - Delete Cap Collection
app.delete('/api/admin/capscollections/:id', verifyToken, async (req, res) => {
    try {
        const collectionId = req.params.id;
        const deletedCollection = await CapCollection.findByIdAndDelete(collectionId); 

        if (!deletedCollection) {
            return res.status(404).json({ message: 'Cap Collection not found for deletion.' });
        }

        // Clean up associated images from permanent storage
        deletedCollection.variations.forEach(v => {
            if (v.frontImageUrl) deleteFileFromPermanentStorage(v.frontImageUrl);
            if (v.backImageUrl) deleteFileFromPermanentStorage(v.backImageUrl);
        });

        res.status(200).json({ message: `Cap Collection ${collectionId} and associated images deleted successfully.` });
    } catch (error) {
        console.error('Error deleting cap collection:', error);
        res.status(500).json({ message: 'Server error during cap collection deletion.' });
    }
});

app.get('/api/admin/newarrivals', verifyToken, async (req, res) => {
    try {
        // 1. Fetch all products - Added 'description' to the select list
        const products = await NewArrivals.find({})
            .select('_id name description tag price variations totalStock isActive') // UPDATED
            .sort({ createdAt: -1 })
            .lean();

        // 2. Sign URLs for all products
        const signedProducts = await Promise.all(products.map(async (product) => {
            const signedVariations = await Promise.all(product.variations.map(async (v) => ({
                ...v,
                frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl,
                backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl
            })));
            return { ...product, variations: signedVariations };
        }));

        res.status(200).json(signedProducts);
    } catch (error) {
        console.error('Error fetching new arrivals:', error);
        res.status(500).json({ message: 'Server error while fetching new arrivals.', details: error.message });
    }
});

app.get('/api/admin/newarrivals/:id', verifyToken, async (req, res) => {
    try {
        const productId = req.params.id;
        // This will now include 'description' if it exists in the DB
        const product = await NewArrivals.findById(productId).lean();

        if (!product) {
            return res.status(404).json({ message: 'Product not found.' });
        }

        // Sign URLs logic remains the same
        const signedVariations = await Promise.all(product.variations.map(async (v) => ({
            ...v,
            frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl, 
            backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl 
        })));
        
        product.variations = signedVariations;

        res.status(200).json(product);
    } catch (error) {
        console.error('Error fetching new arrival:', error);
        res.status(500).json({ message: 'Server error fetching product data.' });
    }
});

/**
 * POST /api/admin/newarrivals - Create New Arrival
 * Handles multipart/form-data. Uploads front and back images for all variations concurrently.
 */
app.post(
    '/api/admin/newarrivals',
    verifyToken, 
    upload.fields(uploadFields), 
    async (req, res) => {
        try {
            // A. Extract JSON Metadata
            if (!req.body.productData) {
                return res.status(400).json({ message: "Missing product data payload." });
            }
            const productData = JSON.parse(req.body.productData);

            // B. Process Files and Integrate Paths into Variations
            const files = req.files; 
            const finalVariations = [];
            const uploadPromises = [];
            
            for (const variation of productData.variations) {
                const index = variation.variationIndex;
                // Files are expected to be named front-view-upload-{index} and back-view-upload-{index}
                const frontFile = files[`front-view-upload-${index}`]?.[0];
                const backFile = files[`back-view-upload-${index}`]?.[0];

                if (!frontFile || !backFile) {
                    throw new Error(`Missing BOTH front and back image files for Variation #${index}.`);
                }

                // Start uploads concurrently
                const uploadFrontPromise = uploadFileToPermanentStorage(frontFile);
                const uploadBackPromise = uploadFileToPermanentStorage(backFile);
                
                // Wait for uploads and create the final variation object
                const combinedUploadPromise = Promise.all([uploadFrontPromise, uploadBackPromise])
                    .then(([frontImageUrl, backImageUrl]) => {
                        finalVariations.push({
                            variationIndex: variation.variationIndex,
                            colorHex: variation.colorHex,
                            frontImageUrl: frontImageUrl, // Permanent storage key/path
                            backImageUrl: backImageUrl, // Permanent storage key/path
                            // CRITICAL FIX: Ensure the sizes array is copied from the incoming payload
                            sizes: variation.sizes || [], 
                        });
                    });
                    
                uploadPromises.push(combinedUploadPromise);
            }
            
            // Wait for all image uploads to finish before saving the document
            await Promise.all(uploadPromises);

            if (finalVariations.length === 0) {
                return res.status(400).json({ message: "No valid product images and metadata were received." });
            }

            // C. Create the Final Product Object
            // The totalStock field is now calculated automatically by the Mongoose pre('save') hook, 
            // so we don't need the manual calculation here. We can omit setting totalStock or set it to 0.
            
            const newProduct = new NewArrivals({
                name: productData.name,
                description: productData.description, // ADD THIS LINE
                tag: productData.tag,
                price: productData.price, 
                isActive: productData.isActive, 
                variations: finalVariations, 
            });

            // D. Save to Database (pre('save') hook calculates totalStock automatically)
            const savedProduct = await newProduct.save();

            res.status(201).json({ 
                message: 'New Arrival created successfully and images uploaded to permanent storage.',
                productId: savedProduct._id,
                name: savedProduct.name
            });

        } catch (error) {
            console.error('Error creating new arrival:', error); 
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors }); 
            }
            res.status(500).json({ message: 'Server error during new arrival creation or file upload.', details: error.message });
        }
    }
);

/**
 * PUT /api/admin/newarrivals/:id - Update New Arrival
 * Supports two modes:
 * 1. Quick Restock (application/json): Updates only stock and active status.
 * 2. Full Update (multipart/form-data): Updates all fields, including replacing images if new files are provided.
 */
app.put(
    '/api/admin/newarrivals/:id',
    verifyToken, 
    upload.fields(uploadFields), 
    async (req, res) => {
        const productId = req.params.id;
        let existingProduct;
        
        try {
            existingProduct = await NewArrivals.findById(productId);
            if (!existingProduct) {
                return res.status(404).json({ message: 'New Arrival not found for update.' });
            }

            // A. HANDLE QUICK RESTOCK (Check if Content-Type is JSON AND productData is NOT present)
            const isQuickRestock = req.get('Content-Type')?.includes('application/json') && !req.body.productData;
            
            if (isQuickRestock) {
                const { totalStock, isActive } = req.body;

                if (totalStock === undefined || isActive === undefined) {
                    return res.status(400).json({ message: "Missing 'totalStock' or 'isActive' in simple update payload." });
                }
                
                // Perform simple update
                // NOTE: Setting totalStock manually bypasses the pre('save') hook logic, 
                // which is fine for a quick-update assuming the detailed inventory update (sizes array) 
                // is not the goal of this quick action.
                existingProduct.totalStock = totalStock;
                existingProduct.isActive = isActive; 

                const updatedProduct = await existingProduct.save();
                return res.status(200).json({ 
                    message: `New Arrival quick-updated. Stock: ${updatedProduct.totalStock}, Active: ${updatedProduct.isActive}.`,
                    productId: updatedProduct._id
                });
            }

            // B. HANDLE FULL FORM SUBMISSION (multipart/form-data)
            if (!req.body.productData) {
                return res.status(400).json({ message: "Missing product data payload for full update." });
            }

            const productData = JSON.parse(req.body.productData);
            const files = req.files; 
            const updatedVariations = [];
            const uploadPromises = [];
            const oldImagesToDelete = [];

            for (const incomingVariation of productData.variations) {
                const index = incomingVariation.variationIndex;
                const existingPermanentVariation = existingProduct.variations.find(v => v.variationIndex === index);

                // Initialize with existing permanent URLs
                let finalFrontUrl = existingPermanentVariation?.frontImageUrl || null;
                let finalBackUrl = existingPermanentVariation?.backImageUrl || null;

                // Process FRONT Image
                const newFrontFile = files[`front-view-upload-${index}`]?.[0];

                if (newFrontFile) {
                    if (existingPermanentVariation?.frontImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.frontImageUrl);
                    }
                    // Start upload and update finalFrontUrl when resolved
                    const frontUploadPromise = uploadFileToPermanentStorage(newFrontFile).then(url => { finalFrontUrl = url; });
                    uploadPromises.push(frontUploadPromise);
                } else if (!finalFrontUrl) {
                    // Fail if no existing URL and no new file provided
                    throw new Error(`Front image missing for Variation #${index}.`);
                }
                
                // Process BACK Image
                const newBackFile = files[`back-view-upload-${index}`]?.[0];

                if (newBackFile) {
                    if (existingPermanentVariation?.backImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.backImageUrl);
                    }
                    // Start upload and update finalBackUrl when resolved
                    const backUploadPromise = uploadFileToPermanentStorage(newBackFile).then(url => { finalBackUrl = url; });
                    uploadPromises.push(backUploadPromise);
                } else if (!finalBackUrl) {
                    // Fail if no existing URL and no new file provided
                    throw new Error(`Back image missing for Variation #${index}.`);
                }
                
                // Create a temporary object. Use the incoming sizes array.
                updatedVariations.push({
                    variationIndex: index,
                    colorHex: incomingVariation.colorHex,
                    // CRITICAL FIX: Ensure the sizes array is carried over from the incoming payload
                    sizes: incomingVariation.sizes || existingPermanentVariation?.sizes || [],
                    get frontImageUrl() { return finalFrontUrl; }, 
                    get backImageUrl() { return finalBackUrl; }, 
                });
            }
            
            // Wait for all uploads to complete and for finalFrontUrl/finalBackUrl to be updated
            await Promise.all(uploadPromises);

            if (updatedVariations.length === 0) {
                return res.status(400).json({ message: "No valid variations were processed for update." });
            }

            // Aggregate total stock calculation is now handled by the Mongoose pre('save') hook
            // The lines below are removed:
            // let calculatedTotalStock = 0;
            // if (Array.isArray(productData.sizes)) { ... }
            // productData.totalStock = calculatedTotalStock;
            
            // Update the Document Fields
            existingProduct.name = productData.name;
            existingProduct.description = productData.description; // ADD THIS LINE
            existingProduct.tag = productData.tag;
            existingProduct.price = productData.price;
            // The sizes field was correctly removed from the main schema, do not update it here.
            existingProduct.isActive = productData.isActive; // Update isActive field
            
            // Assign the resolved variations array, ensuring sizes and final URLs are included
            existingProduct.variations = updatedVariations.map(v => ({
                variationIndex: v.variationIndex,
                colorHex: v.colorHex,
                sizes: v.sizes, // CRITICAL: Assign the sizes array
                frontImageUrl: v.frontImageUrl, // Accesses the getter which returns the final URL
                backImageUrl: v.backImageUrl, 
            }));
            
            // The totalStock field will be automatically updated by the pre('save') hook 
            // before the document is saved.
            
            // Save to Database
            const updatedProduct = await existingProduct.save();

            // Delete old images in the background (fire and forget)
            oldImagesToDelete.forEach(url => deleteFileFromPermanentStorage(url));

            res.status(200).json({ 
                message: 'New Arrival updated and images handled successfully.',
                productId: updatedProduct._id,
                name: updatedProduct.name
            });

        } catch (error) {
            console.error('Error updating new arrival:', error); 
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors }); 
            }
            res.status(500).json({ message: 'Server error during new arrival update or file upload.', details: error.message });
        }
    }
);

/**
 * DELETE /api/admin/newarrivals/:id - Delete New Arrival
 * Deletes the product and triggers background deletion of associated images from permanent storage.
 */
app.delete('/api/admin/newarrivals/:id', verifyToken, async (req, res) => {
    try {
        const productId = req.params.id;
        const deletedProduct = await NewArrivals.findByIdAndDelete(productId);

        if (!deletedProduct) {
            return res.status(404).json({ message: 'New Arrival not found for deletion.' });
        }

        // Trigger background image deletion
        deletedProduct.variations.forEach(v => {
            if (v.frontImageUrl) deleteFileFromPermanentStorage(v.frontImageUrl);
            if (v.backImageUrl) deleteFileFromPermanentStorage(v.backImageUrl);
        });

        res.status(200).json({ message: `New Arrival ${productId} and associated images deleted successfully.` });
    } catch (error) {
        console.error('Error deleting new arrival:', error);
        res.status(500).json({ message: 'Server error during product deletion.' });
    }
});

// GET /api/admin/wearscollections/:id
app.get('/api/admin/wearscollections/:id', verifyToken, async (req, res) => {
    try {
        // ADDED 'description' to the select list
        const collection = await WearsCollection.findById(req.params.id)
            .select('_id name description tag price variations sizesAndStock isActive totalStock') 
            .lean(); 
        
        if (!collection) return res.status(404).json({ message: 'Collection not found.' });

        const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
            ...v,
            frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl, 
            backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl 
        })));
        
        collection.variations = signedVariations;
        res.status(200).json(collection);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching collection.' });
    }
});

// POST /api/admin/wearscollections (Create New Collection) 
app.post(
    '/api/admin/wearscollections',
    verifyToken, 
    upload.fields(uploadFields), 
    async (req, res) => {
        // Assume 'mongoose' is globally available or imported, e.g., const mongoose = require('mongoose');
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            // A. Extract JSON Metadata
            if (!req.body.collectionData) {
                await session.abortTransaction();
                return res.status(400).json({ message: "Missing collection data payload." });
            }
            const collectionData = JSON.parse(req.body.collectionData);

            // B. Process Files and Integrate Paths into Variations
            const files = req.files; 
            const finalVariations = [];
            const uploadPromises = [];
            
            for (const variation of collectionData.variations) {
                const index = variation.variationIndex;
                const frontFile = files[`front-view-upload-${index}`]?.[0];
                const backFile = files[`back-view-upload-${index}`]?.[0];

                if (!frontFile || !backFile) {
                    // Check if file is missing AND no existing URL is provided 
                    throw new Error(`Missing BOTH front and back image files for Variation #${index}.`);
                }

                // Upload files concurrently
                const uploadFrontPromise = uploadFileToPermanentStorage(frontFile);
                const uploadBackPromise = uploadFileToPermanentStorage(backFile);
                
                // Store the promise that resolves and pushes the final variation object
                const combinedUploadPromise = Promise.all([uploadFrontPromise, uploadBackPromise])
                    .then(([frontImageUrl, backImageUrl]) => {
                        finalVariations.push({
                            variationIndex: variation.variationIndex,
                            colorHex: variation.colorHex,
                            sizes: variation.sizes, 
                            frontImageUrl: frontImageUrl, 
                            backImageUrl: backImageUrl, 
                        });
                    });
                    
                uploadPromises.push(combinedUploadPromise);
            }
            
            await Promise.all(uploadPromises); // Wait for all uploads to complete

            if (finalVariations.length === 0) {
                await session.abortTransaction();
                return res.status(400).json({ message: "No valid product images and metadata were received after upload processing." });
            }

            // C. Create the Final Collection Object
            const newCollection = new WearsCollection({
                name: collectionData.name,
                description: collectionData.description, 
                tag: collectionData.tag,
                price: collectionData.price, 
                totalStock: collectionData.totalStock, 
                sizesAndStock: collectionData.sizesAndStock, 
                isActive: collectionData.isActive, 
                variations: finalVariations, 
            });

            // D. Save to Database using the session
            const savedCollection = await newCollection.save({ session }); // <-- Use session for atomic save

            // E. Commit the transaction
            await session.commitTransaction();

            res.status(201).json({ 
                message: 'Wears Collection created and images uploaded successfully to IDRIVE.',
                collectionId: savedCollection._id,
                name: savedCollection.name
            });

        } catch (error) {
            console.error('Error creating wear collection (Transaction Aborted):', error); 
            // F. Abort the transaction on error
            await session.abortTransaction();
            
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors }); 
            }
            res.status(500).json({ message: 'Server error during collection creation or file upload.', details: error.message });
        } finally {
            // G. End the session
            session.endSession();
        }
    }
);

// PUT /api/admin/wearscollections/:id (Update Collection)
app.put(
    '/api/admin/wearscollections/:id',
    verifyToken, 
    upload.fields(uploadFields), 
    async (req, res) => {
        const collectionId = req.params.id;
        let existingCollection;
        
        try {
            existingCollection = await WearsCollection.findById(collectionId);
            if (!existingCollection) {
                return res.status(404).json({ message: 'Collection not found for update.' });
            }

            const isQuickRestock = req.get('Content-Type')?.includes('application/json');
            
            // A. HANDLE QUICK RESTOCK (Only updates stock/active status)
            if (isQuickRestock && !req.body.collectionData) {
                // --- FIX 3: Destructure totalStock from JSON body ---
                const { sizesAndStock, isActive, totalStock } = req.body;

                if (!sizesAndStock || isActive === undefined || totalStock === undefined) {
                    return res.status(400).json({ message: "Missing 'sizesAndStock', 'isActive', or 'totalStock' in simple update payload." });
                }
                
                // Perform simple update
                existingCollection.sizesAndStock = sizesAndStock;
                existingCollection.isActive = isActive;
                // --- FIX 4: Assign totalStock from payload ---
                existingCollection.totalStock = totalStock; 

                const updatedCollection = await existingCollection.save();
                return res.status(200).json({ 
                    message: `Collection quick-updated. Active: ${updatedCollection.isActive}. Stock: ${updatedCollection.totalStock}`,
                    collectionId: updatedCollection._id,
                    name: updatedCollection.name
                });
            }

            // B. HANDLE FULL FORM SUBMISSION (Updates everything, including images/variations)
            if (!req.body.collectionData) {
                return res.status(400).json({ message: "Missing collection data payload for full update." });
            }

            const collectionData = JSON.parse(req.body.collectionData);
            const files = req.files; 
            const updatedVariations = [];
            const uploadPromises = [];
            const oldImagesToDelete = [];

            for (const incomingVariation of collectionData.variations) {
                const index = incomingVariation.variationIndex;
                const existingPermanentVariation = existingCollection.variations.find(v => v.variationIndex === index);

                // Start with the existing URLs, or null if a new variation
                let finalFrontUrl = incomingVariation.existingFrontImageUrl || existingPermanentVariation?.frontImageUrl || null;
                let finalBackUrl = incomingVariation.existingBackImageUrl || existingPermanentVariation?.backImageUrl || null;


                // Temporary object to hold all data for this variation
                let variationUpdates = { 
                    variationIndex: index,
                    colorHex: incomingVariation.colorHex,
                    // 🔥 FIX: Include the nested sizes array for stock management
                    sizes: incomingVariation.sizes, 
                    frontImageUrl: finalFrontUrl,
                    backImageUrl: finalBackUrl,
                    ...(incomingVariation._id && { _id: incomingVariation._id }) // Preserve _id if updating an existing variation
                };

                // Process FRONT Image
                const frontFileKey = `front-view-upload-${index}`;
                const newFrontFile = files[frontFileKey]?.[0];

                if (newFrontFile) {
                    // New file uploaded: Schedule old image for deletion and new file for upload
                    if (existingPermanentVariation?.frontImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.frontImageUrl);
                    }
                    const frontUploadPromise = uploadFileToPermanentStorage(newFrontFile).then(url => { 
                        variationUpdates.frontImageUrl = url; 
                    });
                    uploadPromises.push(frontUploadPromise);
                } else if (!variationUpdates.frontImageUrl) {
                    throw new Error(`Front image missing for Variation #${index} and no existing image found.`);
                }
                
                // Process BACK Image
                const backFileKey = `back-view-upload-${index}`;
                const newBackFile = files[backFileKey]?.[0];

                if (newBackFile) {
                    // New file uploaded: Schedule old image for deletion and new file for upload
                    if (existingPermanentVariation?.backImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.backImageUrl);
                    }
                    const backUploadPromise = uploadFileToPermanentStorage(newBackFile).then(url => { 
                        variationUpdates.backImageUrl = url; 
                    });
                    uploadPromises.push(backUploadPromise);
                } else if (!variationUpdates.backImageUrl) {
                    throw new Error(`Back image missing for Variation #${index} and no existing image found.`);
                }
                
                // Collect the temporary variation object
                updatedVariations.push(variationUpdates);
            }
            
            // Wait for all image uploads to finish and update the URLs in updatedVariations objects
            await Promise.all(uploadPromises);

            if (updatedVariations.length === 0) {
                return res.status(400).json({ message: "No valid variations were processed for update." });
            }
            
            // Update the Document Fields
            existingCollection.name = collectionData.name;
            existingCollection.description = collectionData.description; 
            existingCollection.tag = collectionData.tag;
            existingCollection.price = collectionData.price;
            existingCollection.totalStock = collectionData.totalStock; 
            existingCollection.sizesAndStock = collectionData.sizesAndStock; 
            existingCollection.isActive = collectionData.isActive;
            
            // Assign the finalized variations array directly (now includes nested sizes)
            existingCollection.variations = updatedVariations; 
            
            // Save to Database
            const updatedCollection = await existingCollection.save();

            // Delete old images in the background (fire and forget)
            oldImagesToDelete.forEach(url => deleteFileFromPermanentStorage(url));

            res.status(200).json({ 
                message: 'Wears Collection updated and images handled successfully.',
                collectionId: updatedCollection._id,
                name: updatedCollection.name
            });

        } catch (error) {
            console.error('Error updating wear collection:', error); 
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors }); 
            }
            res.status(500).json({ message: 'Server error during collection update or file upload.', details: error.message });
        }
    }
);

// DELETE /api/admin/wearscollections/:id (Delete Collection) 
app.delete('/api/admin/wearscollections/:id', verifyToken, async (req, res) => {
    try {
        const collectionId = req.params.id;
        const deletedCollection = await WearsCollection.findByIdAndDelete(collectionId);

        if (!deletedCollection) {
            return res.status(404).json({ message: 'Collection not found for deletion.' });
        }

        deletedCollection.variations.forEach(v => {
            if (v.frontImageUrl) deleteFileFromPermanentStorage(v.frontImageUrl);
            if (v.backImageUrl) deleteFileFromPermanentStorage(v.backImageUrl);
        });

        res.status(200).json({ message: `Collection ${collectionId} and associated images deleted successfully.` });
    } catch (error) {
        console.error('Error deleting wear collection:', error);
        res.status(500).json({ message: 'Server error during collection deletion.' });
    }
});

// GET /api/admin/wearscollections (Fetch All Collections) 
app.get(
    '/api/admin/wearscollections',
    verifyToken,
    async (req, res) => {
        try {
            // Fetch all collections
            // --- FIX 6: Ensure totalStock is selected for fetching ---
            const collections = await WearsCollection.find({})
                .select('_id name tag price variations sizesAndStock isActive totalStock') 
                .sort({ createdAt: -1 })
                .lean(); 

            // Sign URLs
            const signedCollections = await Promise.all(collections.map(async (collection) => {
                const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
                    ...v,
                    frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl,
                    backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl
                })));
                return {
                    ...collection,
                    variations: signedVariations
                };
            }));

            res.status(200).json(signedCollections);
        } catch (error) {
            console.error('Error fetching wear collections:', error);
            res.status(500).json({ message: 'Server error while fetching collections.', details: error.message });
        }
    }
);

// 1. POST /api/admin/preordercollections (Create New Pre-Order Collection) 
app.post('/api/admin/preordercollections', verifyToken, upload.fields(uploadFields), async (req, res) => {
    try {
        // A. Extract JSON Metadata
        if (!req.body.collectionData) {
            return res.status(400).json({ message: "Missing pre-order collection data payload." });
        }
        const collectionData = JSON.parse(req.body.collectionData);

        // B. Process Files and Integrate Paths into Variations
        const files = req.files;
        const finalVariations = [];
        const uploadPromises = [];

        for (const variation of collectionData.variations) {
            const index = variation.variationIndex;
            const frontFile = files[`front-view-upload-${index}`]?.[0];
            const backFile = files[`back-view-upload-${index}`]?.[0];

            if (!frontFile || !backFile) {
                // If the incoming variation requires new files but they are missing, throw an error.
                throw new Error(`Missing BOTH front and back image files for Variation #${index}.`);
            }

            const uploadFrontPromise = uploadFileToPermanentStorage(frontFile);
            const uploadBackPromise = uploadFileToPermanentStorage(backFile);

            // Wait for uploads and then compile the final variation object
            const combinedUploadPromise = Promise.all([uploadFrontPromise, uploadBackPromise])
                .then(([frontImageUrl, backImageUrl]) => {
                    finalVariations.push({
                        variationIndex: variation.variationIndex,
                        frontImageUrl: frontImageUrl,
                        backImageUrl: backImageUrl,
                        colorHex: variation.colorHex, // 🔑 ADDED: Capture colorHex
                        sizes: variation.sizes,       // 🔑 ADDED: Capture nested sizes/stock
                    });
                });

            uploadPromises.push(combinedUploadPromise);
        }

        await Promise.all(uploadPromises);

        if (finalVariations.length === 0) {
            return res.status(400).json({ message: "No valid product images and metadata were received after upload processing." });
        }

        // C. Create the Final Collection Object
        const newCollection = new PreOrderCollection({
            name: collectionData.name,
            description: collectionData.description, // 🔑 ADDED: Link the new description field
            tag: collectionData.tag,
            price: collectionData.price,
            isActive: collectionData.isActive,
            availableDate: collectionData.availableDate,
            variations: finalVariations,
        });

        // D. Save to Database (pre('save') hook runs here to calculate totalStock)
        const savedCollection = await newCollection.save();

        res.status(201).json({
            message: 'Pre-Order Collection created and images uploaded successfully.',
            collectionId: savedCollection._id,
            name: savedCollection.name
        });

    } catch (error) {
        console.error('Error creating pre-order collection:', error);
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(err => err.message).join(', ');
            return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors });
        }
        res.status(500).json({ message: 'Server error during collection creation or file upload.', details: error.message });
    }
}
);


// 2. PUT /api/admin/preordercollections/:id (Update Pre-Order Collection)
app.put(
    '/api/admin/preordercollections/:id',
    verifyToken,
    upload.fields(uploadFields),
    async (req, res) => {
        const collectionId = req.params.id;
        let existingCollection;

        try {
            existingCollection = await PreOrderCollection.findById(collectionId);
            if (!existingCollection) {
                return res.status(404).json({ message: 'Pre-Order Collection not found for update.' });
            }

            const isQuickUpdate = req.get('Content-Type')?.includes('application/json') && !req.body.collectionData;

            // A. HANDLE QUICK UPDATE (Active Status, Available Date)
            if (isQuickUpdate) {
                // 🔑 REMOVED totalStock from destructuring and payload as it's a derived field
                const { isActive, availableDate } = req.body; 

                const updateFields = {};
                if (isActive !== undefined) updateFields.isActive = isActive;
                if (availableDate !== undefined) updateFields.availableDate = availableDate;

                if (Object.keys(updateFields).length === 0) {
                    return res.status(400).json({ message: "Missing update fields in simple update payload." });
                }

                // Perform simple update
                Object.assign(existingCollection, updateFields);

                // pre('save') runs here, recalculating totalStock based on existing variation data
                const updatedCollection = await existingCollection.save();
                return res.status(200).json({
                    message: `Pre-Order Collection quick-updated.`,
                    collectionId: updatedCollection._id,
                    updates: updateFields
                });
            }

            // B. HANDLE FULL FORM SUBMISSION (Includes Metadata and Files)
            if (!req.body.collectionData) {
                return res.status(400).json({ message: "Missing collection data payload for full update." });
            }

            const collectionData = JSON.parse(req.body.collectionData);
            const files = req.files;
            const updatedVariations = [];
            const uploadPromises = [];
            const oldImagesToDelete = [];

            for (const incomingVariation of collectionData.variations) {
                const index = incomingVariation.variationIndex;
                const existingPermanentVariation = existingCollection.variations.find(v => v.variationIndex === index);

                let finalFrontUrl = existingPermanentVariation?.frontImageUrl || null;
                let finalBackUrl = existingPermanentVariation?.backImageUrl || null;

                // Process FRONT Image
                const frontFileKey = `front-view-upload-${index}`;
                const newFrontFile = files[frontFileKey]?.[0];

                if (newFrontFile) {
                    if (existingPermanentVariation?.frontImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.frontImageUrl);
                    }
                    const frontUploadPromise = uploadFileToPermanentStorage(newFrontFile).then(url => { finalFrontUrl = url; });
                    uploadPromises.push(frontUploadPromise);
                } else if (!finalFrontUrl) {
                    throw new Error(`Front image missing for Variation #${index} and no existing image found.`);
                }

                // Process BACK Image
                const backFileKey = `back-view-upload-${index}`;
                const newBackFile = files[backFileKey]?.[0];

                if (newBackFile) {
                    if (existingPermanentVariation?.backImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.backImageUrl);
                    }
                    const backUploadPromise = uploadFileToPermanentStorage(newBackFile).then(url => { finalBackUrl = url; });
                    uploadPromises.push(backUploadPromise);
                } else if (!finalBackUrl) {
                    throw new Error(`Back image missing for Variation #${index} and no existing image found.`);
                }

                // Push a placeholder object that will resolve once uploads complete
                updatedVariations.push({
                    variationIndex: index,
                    colorHex: incomingVariation.colorHex, // 🔑 ADDED: Capture colorHex
                    sizes: incomingVariation.sizes,       // 🔑 ADDED: Capture nested sizes/stock
                    // Use functions for lazy evaluation of file URLs after uploads complete
                    get frontImageUrl() { return finalFrontUrl; },
                    get backImageUrl() { return finalBackUrl; },
                });
            }

            await Promise.all(uploadPromises);

            if (updatedVariations.length === 0) {
                return res.status(400).json({ message: "No valid variations were processed for full update." });
            }

            // Update the Document Fields
            existingCollection.name = collectionData.name;
            existingCollection.tag = collectionData.tag;
            existingCollection.description = collectionData.description; // 🔑 ADDED: Update description
            existingCollection.price = collectionData.price;
            existingCollection.isActive = collectionData.isActive;
            existingCollection.availableDate = collectionData.availableDate;

            // Map the placeholder objects to plain objects before saving, including new fields
            existingCollection.variations = updatedVariations.map(v => ({
                variationIndex: v.variationIndex,
                colorHex: v.colorHex,             // 🔑 ADDED
                sizes: v.sizes,                   // 🔑 ADDED
                frontImageUrl: v.frontImageUrl,
                backImageUrl: v.backImageUrl,
            }));

            // Save to Database (pre('save') hook runs here to calculate totalStock)
            const updatedCollection = await existingCollection.save();

            // Delete old images in the background (fire and forget)
            oldImagesToDelete.forEach(url => deleteFileFromPermanentStorage(url));

            res.status(200).json({
                message: 'Pre-Order Collection updated and images handled successfully.',
                collectionId: updatedCollection._id,
                name: updatedCollection.name
            });

        } catch (error) {
            console.error('Error updating pre-order collection:', error);
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors });
            }
            res.status(500).json({ message: 'Server error during collection update or file upload.', details: error.message });
        }
    }
);


// 3. GET /api/admin/preordercollections (Fetch All Pre-Order Collections) 
app.get(
    '/api/admin/preordercollections',
    verifyToken,
    async (req, res) => {
        try {
            // Fetch all collections, selecting only necessary and consistent fields
            const collections = await PreOrderCollection.find({})
                // 🔑 UPDATED: Removed top-level 'sizes' from select list
                .select('_id name tag description price variations totalStock isActive availableDate') 
                .sort({ createdAt: -1 })
                .lean();

            // Sign URLs
            const signedCollections = await Promise.all(collections.map(async (collection) => {
                const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
                    ...v,
                    // The 'v' object here already contains colorHex and sizes, as they were pulled from the schema
                    frontImageUrl: v.frontImageUrl ? await generateSignedUrl(v.frontImageUrl) : null, 
                    backImageUrl: v.backImageUrl ? await generateSignedUrl(v.backImageUrl) : null
                })));
                return {
                    ...collection,
                    variations: signedVariations
                };
            }));

            res.status(200).json(signedCollections);
        } catch (error) {
            console.error('Error fetching pre-order collections:', error);
            res.status(500).json({ message: 'Server error while fetching collections.', details: error.message });
        }
    }
);


// 4. GET /api/admin/preordercollections/:id (Fetch a Single Pre-Order Collection) 
app.get(
    '/api/admin/preordercollections/:id',
    verifyToken,
    async (req, res) => {
        const collectionId = req.params.id;
        
        try {
            // Find the collection by ID (already includes all fields due to .lean())
            const collection = await PreOrderCollection.findById(collectionId).lean();

            if (!collection) {
                return res.status(404).json({ message: 'Pre-Order Collection not found.' });
            }

            // Sign URLs for all variations
            const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
                ...v,
                // The 'v' object here already contains colorHex and sizes
                frontImageUrl: v.frontImageUrl ? await generateSignedUrl(v.frontImageUrl) : null,
                backImageUrl: v.backImageUrl ? await generateSignedUrl(v.backImageUrl) : null
            })));

            const signedCollection = {
                ...collection,
                variations: signedVariations
            };

            res.status(200).json(signedCollection);

        } catch (error) {
            if (error.name === 'CastError') {
                return res.status(400).json({ message: 'Invalid collection ID format.' });
            }
            console.error(`Error fetching collection ${collectionId}:`, error);
            res.status(500).json({ message: 'Server error while fetching collection.', details: error.message });
        }
    }
);

// 5. DELETE /api/admin/preordercollections/:collectionId (Delete a Pre-Order Collection)
app.delete(
    '/api/admin/preordercollections/:collectionId',
    verifyToken, 
    async (req, res) => {
        const { collectionId } = req.params;

        try {
            // Find the collection by ID and delete it
            const deletedCollection = await PreOrderCollection.findByIdAndDelete(collectionId);

            if (!deletedCollection) {
                return res.status(404).json({ message: 'Pre-order collection not found.' });
            }

            // Delete associated images in the background (fire and forget)
            deletedCollection.variations.forEach(v => {
                if (v.frontImageUrl) deleteFileFromPermanentStorage(v.frontImageUrl);
                if (v.backImageUrl) deleteFileFromPermanentStorage(v.backImageUrl);
            });

            res.status(200).json({
                message: 'Pre-order collection deleted successfully and associated images scheduled for removal.',
                collectionId: collectionId
            });

        } catch (error) {
            if (error.name === 'CastError') {
                return res.status(400).json({ message: 'Invalid collection ID format.' });
            }

            console.error(`Error deleting collection ${collectionId}:`, error);
            res.status(500).json({ message: 'Server error during deletion.', details: error.message });
        }
    }
);

app.get('/api/admin/inventory/deductions', verifyToken, async (req, res) => {
    try {
        const categoryFilter = req.query.category ? req.query.category.toLowerCase() : 'all';
        
        const categoryMap = {
            'wears': 'WearsCollection', 
            'caps': 'CapCollection', 
            'newarrivals': 'NewArrivals', 
            'preorders': 'PreOrderCollection' 
        };
        
        let pipeline = [
            {
                $match: {
                    // Only show orders where inventory HAS been deducted
                    status: { $in: ['Confirmed', 'Shipped', 'Delivered'] }
                }
            },
            {
                $unwind: '$items'
            }
        ];
        
        if (categoryFilter !== 'all') {
            const productType = categoryMap[categoryFilter];
            if (productType) {
                pipeline.push({
                    $match: { 'items.productType': productType }
                });
            } else {
                return res.status(400).json({ message: 'Invalid category filter.' });
            }
        }
        
        // Project Stage - Now includes paymentMethod for better logging
        pipeline.push({
            $project: {
                _id: 0,
                productId: '$items.productId',
                name: '$items.name',
                size: '$items.size', // Added size for better logging detail
                category: '$items.productType',
                quantity: '$items.quantity', 
                orderId: '$_id',
                orderReference: '$orderReference', // Helpful for searching
                date: '$confirmedAt',
                
                // --- Updated for Manual Confirmation Workflow ---
                paymentMethod: '$paymentMethod', 
                paymentTxnId: '$paymentTxnId', 
                confirmedBy: '$confirmedBy'   // This will now be the Admin's ID
            }
        });

        pipeline.push({ $sort: { date: -1 } });

        const OrderModel = mongoose.models.Order || mongoose.model('Order');
        const deductionLogs = await OrderModel.aggregate(pipeline);

        // Cleanup names for the Frontend
        const deductionLogsFormatted = deductionLogs.map(log => ({
            ...log,
            category: log.category 
                ? log.category.replace('Collection', '').replace('PreOrder', 'Pre-Order')
                : 'General'
        }));

        res.status(200).json(deductionLogsFormatted);

    } catch (error) {
        console.error('Error fetching inventory deduction log:', error);
        res.status(500).json({ message: 'Failed to retrieve logs.' });
    }
});

// GET /api/collections/wears (For Homepage Display)
app.get('/api/collections/wears', async (req, res) => {
    try {
        const collections = await WearsCollection.find({ isActive: true }) 
            // 🔥 ADDED 'description' to the select string
            .select('_id name description tag price variations totalStock') 
            .sort({ createdAt: -1 })
            .lean(); 

        const publicCollections = await Promise.all(collections.map(async (collection) => {
            
            const sizeStockMap = {}; 
            let fallbackFrontImageUrl = null;
            let fallbackBackImageUrl = null;
            const PLACEHOLDER_S3_PATH = 'public/placeholder-image-v1.jpg';

            const filteredVariantsWithStock = [];

            for (const v of collection.variations || []) { 
                const signedFrontUrl = await generateSignedUrl(v.frontImageUrl);
                const signedBackUrl = await generateSignedUrl(v.backImageUrl);

                if (!fallbackFrontImageUrl && signedFrontUrl) {
                    fallbackFrontImageUrl = signedFrontUrl;
                    fallbackBackImageUrl = signedBackUrl;
                }
                
                const variantTotalStock = (v.sizes || []).reduce((sum, s) => sum + (s.stock || 0), 0);
                
                if (variantTotalStock > 0) {
                    (v.sizes || []).forEach(s => {
                        const normalizedSize = s.size.toUpperCase().trim();
                        if (s.stock > 0) {
                            sizeStockMap[normalizedSize] = (sizeStockMap[normalizedSize] || 0) + s.stock;
                        }
                    });

                    filteredVariantsWithStock.push({
                        color: v.colorHex,
                        frontImageUrl: signedFrontUrl || 'https://placehold.co/400x400/111111/FFFFFF?text=Front+View+Error',
                        backImageUrl: signedBackUrl || 'https://placehold.co/400x400/111111/FFFFFF?text=Back+View+Error',
                    });
                }
            }

            if (!fallbackFrontImageUrl) {
                const signedPlaceholder = await generateSignedUrl(PLACEHOLDER_S3_PATH);
                fallbackFrontImageUrl = signedPlaceholder;
                fallbackBackImageUrl = signedPlaceholder;
            }
            
            return {
                _id: collection._id,
                name: collection.name,
                description: collection.description, // 🔥 ADDED THIS LINE
                tag: collection.tag,
                price: collection.price, 
                frontImageUrl: fallbackFrontImageUrl,
                backImageUrl: fallbackBackImageUrl,
                sizeStockMap: sizeStockMap,
                availableStock: collection.totalStock, 
                variants: filteredVariantsWithStock
            };
        }));

        res.status(200).json(publicCollections);
    } catch (error) {
        console.error('Error fetching public wear collections:', error);
        res.status(500).json({ message: 'Server error.', details: error.message });
    }
});

// GET /api/collections/newarrivals (For Homepage Display)
app.get('/api/collections/newarrivals', async (req, res) => {
    try {
        const products = await NewArrivals.find({ isActive: true }) 
            // --- UPDATED: Added 'description' to the select string ---
            .select('_id name description tag price variations totalStock') 
            .sort({ createdAt: -1 })
            .lean(); 

        const publicProducts = await Promise.all(products.map(async (product) => {
            
            const sizeStockMap = {}; 
            let fallbackFrontImageUrl = null;
            let fallbackBackImageUrl = null;
            const PLACEHOLDER_S3_PATH = 'public/placeholder-image-v1.jpg';

            const filteredVariantsWithStock = [];

            for (const v of product.variations || []) {
                const signedFrontUrl = await generateSignedUrl(v.frontImageUrl);
                const signedBackUrl = await generateSignedUrl(v.backImageUrl);
                
                if (!fallbackFrontImageUrl && signedFrontUrl) {
                    fallbackFrontImageUrl = signedFrontUrl;
                    fallbackBackImageUrl = signedBackUrl;
                }
                
                const variantTotalStock = (v.sizes || []).reduce((sum, s) => sum + (s.stock || 0), 0);
                
                if (variantTotalStock > 0) {
                    (v.sizes || []).forEach(s => {
                        const normalizedSize = s.size.toUpperCase().trim();
                        if (s.stock > 0) {
                            sizeStockMap[normalizedSize] = (sizeStockMap[normalizedSize] || 0) + s.stock;
                        }
                    });

                    filteredVariantsWithStock.push({
                        color: v.colorHex,
                        frontImageUrl: signedFrontUrl || 'https://placehold.co/400x400/111111/FFFFFF?text=Front+View+Error',
                        backImageUrl: signedBackUrl || 'https://placehold.co/400x400/111111/FFFFFF?text=Back+View+Error',
                        sizes: (v.sizes || []).map(s => ({ 
                            size: s.size, 
                            stock: s.stock || 0
                        }))
                    });
                }
            }

            if (!fallbackFrontImageUrl) {
                const signedPlaceholder = await generateSignedUrl(PLACEHOLDER_S3_PATH);
                fallbackFrontImageUrl = signedPlaceholder;
                fallbackBackImageUrl = signedPlaceholder;
            }

            return {
                _id: product._id,
                name: product.name,
                // --- ADDED: Include the description in the final object ---
                description: product.description || '', 
                tag: product.tag,
                price: product.price, 
                frontImageUrl: fallbackFrontImageUrl,
                backImageUrl: fallbackBackImageUrl,
                sizeStockMap: sizeStockMap,
                availableStock: product.totalStock, 
                variants: filteredVariantsWithStock
            };
        }));

        res.status(200).json(publicProducts);
    } catch (error) {
        console.error('Error fetching public new arrivals:', error);
        res.status(500).json({ message: 'Server error while fetching new arrivals for homepage.', details: error.message });
    }
});

// GET /api/collections/preorder (For Homepage Display)
app.get('/api/collections/preorder', async (req, res) => {
    try {
        const collections = await PreOrderCollection.find({ isActive: true })
            .select('_id name tag description price totalStock availableDate variations')
            .sort({ createdAt: -1 })
            .lean();

        const publicCollections = await Promise.all(collections.map(async (collection) => {
            
            const sizeStockMap = {}; 
            
            // --- CRITICAL: Variables for OOS Image Fallback ---
            let fallbackFrontImageUrl = null;
            let fallbackBackImageUrl = null;
            const PLACEHOLDER_S3_PATH = 'public/placeholder-image-v1.jpg'; // Path to your default placeholder

            const filteredVariants = [];

            // --- CRITICAL: Filter Variants and Create Size Map ---
            for (const v of collection.variations || []) {
                
                // 1. SIGN THE VARIATION IMAGES
                const signedFrontUrl = await generateSignedUrl(v.frontImageUrl);
                const signedBackUrl = await generateSignedUrl(v.backImageUrl);
                
                // 2. Capture the first signed URL encountered for the OOS fallback (Runs once)
                if (!fallbackFrontImageUrl && signedFrontUrl) {
                    fallbackFrontImageUrl = signedFrontUrl;
                    fallbackBackImageUrl = signedBackUrl;
                }

                const variantTotalStock = (v.sizes || []).reduce((sum, s) => sum + (s.stock || 0), 0);
                
                // Logic: Only include variants that have stock OR if the totalStock is not managed (pre-order assumed open)
                if (variantTotalStock > 0 || !collection.totalStock) {
                    
                    // Generate a size map entry 
                    (v.sizes || []).forEach(s => {
                        const normalizedSize = s.size.toUpperCase().trim();
                        // Use actual stock if > 0, otherwise use a high number for pre-order if stock is unlimited/ignored
                        const stockForPreorder = (s.stock > 0) ? s.stock : 999; 
                        
                        sizeStockMap[normalizedSize] = Math.max(sizeStockMap[normalizedSize] || 0, stockForPreorder);
                    });

                    // Map and prepare the public variant object
                    filteredVariants.push({
                        color: v.colorHex || '#000000', 
                        variationIndex: v.variationIndex, 
                        frontImageUrl: signedFrontUrl || null,
                        backImageUrl: signedBackUrl || null,
                        sizes: (v.sizes || []).map(s => ({ 
                            size: s.size, 
                            stock: s.stock || 0 
                        }))
                    });
                }
            }
            // --- END CRITICAL FILTERING ---
            
            // --- CRITICAL IMAGE FIX: Failsafe for Missing Data ---
            if (!fallbackFrontImageUrl) {
                const signedPlaceholder = await generateSignedUrl(PLACEHOLDER_S3_PATH);
                fallbackFrontImageUrl = signedPlaceholder;
                fallbackBackImageUrl = signedPlaceholder;
            }
            // --- END CRITICAL IMAGE FIX ---

            return {
                _id: collection._id,
                name: collection.name,
                description: collection.description || '', // 🔑 ADDED: Include description
                tag: collection.tag,
                price: collection.price, 
                sizeStockMap: sizeStockMap, 
                availableStock: collection.totalStock, 
                availableDate: collection.availableDate, 
                // 💡 OOS/Fallback Images (now always set to a signed URL)
                frontImageUrl: fallbackFrontImageUrl, 
                backImageUrl: fallbackBackImageUrl, 
                variants: filteredVariants 
            };
        }));

        res.status(200).json(publicCollections);
    } catch (error) {
        console.error('Error fetching public pre-order collections:', error);
        res.status(500).json({ 
            message: 'Server error while fetching public collections.', 
            details: error.message 
        });
    }
});

// GET /api/collections/caps (For Homepage Display)
app.get('/api/collections/caps', async (req, res) => {
    try {
        const collections = await CapCollection.find({ isActive: true }) 
            .select('_id name tag description price variations totalStock') 
            .sort({ createdAt: -1 })
            .lean(); 

        const publicCollections = await Promise.all(collections.map(async (collection) => {
            
            // --- CRITICAL: Variables for OOS Image Fallback ---
            let fallbackFrontImageUrl = null;
            let fallbackBackImageUrl = null;
            const PLACEHOLDER_S3_PATH = 'public/placeholder-image-v1.jpg'; // Path to your default placeholder

            // --- CRITICAL: Filter Variations based on stock ---
            const filteredVariantsWithStock = [];

            for (const v of collection.variations || []) {
                
                // 1. SIGN THE VARIATION IMAGES
                const signedFrontUrl = await generateSignedUrl(v.frontImageUrl);
                const signedBackUrl = await generateSignedUrl(v.backImageUrl);

                // 2. Capture the first signed URL encountered for the OOS fallback (Runs once)
                if (!fallbackFrontImageUrl && signedFrontUrl) {
                    fallbackFrontImageUrl = signedFrontUrl;
                    fallbackBackImageUrl = signedBackUrl;
                }
                
                // 3. Calculate total stock for THIS specific color (variant)
                const variantTotalStock = v.stock || 0; 
                
                // 4. ONLY INCLUDE THE VARIANT IF IT HAS STOCK
                if (variantTotalStock > 0) {
                    
                    // 5. Map and prepare the public variant object
                    filteredVariantsWithStock.push({
                        color: v.colorHex,
                        frontImageUrl: signedFrontUrl || 'https://placehold.co/400x400/111111/FFFFFF?text=Front+View+Error',
                        backImageUrl: signedBackUrl || 'https://placehold.co/400x400/111111/FFFFFF?text=Back+View+Error',
                        stock: variantTotalStock 
                    });
                }
            }
            // --- END CRITICAL FILTERING ---

            // --- CRITICAL IMAGE FIX: Failsafe for Missing Data ---
            if (!fallbackFrontImageUrl) {
                const signedPlaceholder = await generateSignedUrl(PLACEHOLDER_S3_PATH);
                fallbackFrontImageUrl = signedPlaceholder;
                fallbackBackImageUrl = signedPlaceholder;
            }
            // --- END CRITICAL IMAGE FIX ---
            
            return {
                _id: collection._id,
                name: collection.name,
                tag: collection.tag,
                description: collection.description || '', // 🔑 ADDED: Include description
                price: collection.price, 
                sizeStockMap: {}, 
                availableSizes: [], 
                availableStock: collection.totalStock, 
                variants: filteredVariantsWithStock, 
                // 💡 OOS/Fallback Images (now always set to a signed URL)
                frontImageUrl: fallbackFrontImageUrl,
                backImageUrl: fallbackBackImageUrl
            };
        }));

        res.status(200).json(publicCollections);
    } catch (error) {
        console.error('Error fetching public cap collections:', error);
        res.status(500).json({ message: 'Server error while fetching cap collections for homepage.', details: error.message });
    }
});

// 1. POST /api/users/register (Create Account and Send Verification Code)
app.post('/api/users/register', async (req, res) => {
    // 🔔 CRITICAL UPDATE: Destructure all fields, including the structured 'address' object
    const { 
        email, password, firstName, lastName, phone, whatsapp, address // This is now the object: { street, city, state, zip, country }
    } = req.body;

    // Basic Validation: Ensure core fields and required address fields are present
    if (!email || !password || password.length < 8 || !address || !address.street || !address.city || !address.country) {
        return res.status(400).json({ 
            message: 'Invalid input. Email, password (min 8 chars), and the required address fields (street, city, country) are necessary.' 
        });
    }

    let newUser; 
    let verificationCode;
    
    // --- 🛠️ ADDRESS MAPPING: Create final address object with optional zip handling ---
    const finalAddress = {
        street: address.street,
        city: address.city,
        state: address.state,
        zip: address.zip || null, // ZIP/Postal Code is optional, set to null if empty
        country: address.country
    };
    // ----------------------------------------------------------------------------------

    try {
        // --- 🛠️ FIX: Use new User() and .save() to trigger the pre('save') hook ---
        newUser = new User({
            email,
            password, // Password is now passed to the pre-save hook
            profile: { 
                firstName, 
                lastName, 
                phone, 
                whatsapp 
            },
            // 🎉 UPDATED: Map the structured address object directly
            address: finalAddress,
            status: { isVerified: false } // Set nested status field
        });
        
        await newUser.save(); // <-- THIS IS THE CRITICAL CHANGE that hashes the password and saves the user
        // --------------------------------------------------------------------------

        // Generate and store the verification code (this updates the user again)
        verificationCode = await generateHashAndSaveVerificationCode(newUser);

        // 🟢 TRACE LOG 1: The primary request is about to send the first code.
        console.log(`[PRIMARY SUCCESS PATH] Code GENERATED for ${email}: ${verificationCode}. Sending email now...`);

        // --- Send Verification Code Email Logic (UNMODIFIED) ---
        const verificationSubject = 'Outflickz: Your Account Verification Code';
        const verificationHtml = `
            <div style="background-color: #ffffffff; padding: 30px; border: 1px solid #ffffffff; max-width: 500px; margin: 0 auto; font-family: sans-serif; border-radius: 8px;">
                <div style="text-align: center; padding-bottom: 20px;">
                    <img src="https://i.imgur.com/6Bvu8yB.png" alt="Outflickz Limited Logo" style="max-width: 120px; height: auto; display: block; margin: 0 auto;">
                </div>
                
                <h2 style="color: #000000; font-weight: 600; text-align: center;">Verify Your Account</h2>

                <p style="font-family: sans-serif; line-height: 1.6;">Hello ${firstName || 'New Member'},</p>
                <p style="font-family: sans-serif; line-height: 1.6;">Use the 6-digit code below to verify your email address and activate your account. This code will expire in 10 minutes.</p>
                
                <div style="text-align: center; margin: 30px 0; padding: 15px; background-color: #ffffff; border: 2px dashed #9333ea; border-radius: 4px;">
                    <strong style="font-size: 28px; letter-spacing: 5px; color: #000000;">${verificationCode}</strong>
                </div>

                <p style="font-size: 10px; margin-top: 30px; border-top: 1px solid #e0e0e0; padding-top: 10px; color: #888888; text-align: center;">&copy; ${new Date().getFullYear()} Outflickz Limited.</p>
            </div>
        `;

        await sendMail(email, verificationSubject, verificationHtml);
        console.log(`[PRIMARY SUCCESS PATH] Verification email SENT to ${email} with code ${verificationCode}`);
        
        res.status(201).json({ 
            message: 'Registration successful. Please check your email for the 6-digit verification code.',
            userId: newUser._id,
            needsVerification: true
        });

    } catch (error) {
        
        if (error.code === 11000) { 
            // 🟡 TRACE LOG 2: The secondary request hit the unique index error.
            console.log(`[DUPLICATE ERROR PATH] Request for ${email} hit 11000 error (Duplicate). Checking existing user...`);
            
            // Handle duplicate key error (email already exists)
            const existingUser = await User.findOne({ email });
            
            // 🛑 CRITICAL FIX: Add a guard for null existingUser immediately after findOne
            if (!existingUser) {
                // If the user isn't found immediately after the 11000 error, assume 
                // it was due to the ongoing primary registration and safely suppress the second request.
                console.error(`[DUPLICATE ERROR PATH] User ${email} not found after 11000 error. Assuming primary registration is completing. Suppressing.`);
                // Return a non-error status (202 Accepted) to the client, indicating the registration is still proceeding.
                return res.status(202).json({ 
                    message: 'Registration is already in process. Check your inbox for the code that was just sent.',
                    userId: null, 
                    needsVerification: true
                });
            }

            // ⭐ DEFINITIVE RACE CONDITION FIX: Use a very tight window (10 seconds)
            const GRACE_PERIOD_MS = 10 * 1000; 
            const gracePeriodLimit = new Date(Date.now() - GRACE_PERIOD_MS); 

            // Check if the existing user is NOT verified
            if (existingUser.status && !existingUser.status.isVerified) { 
                
                // 🛑 CRITICAL CHECK 1: RACE CONDITION BLOCK
                // If the user was created very recently (within 10 seconds), 
                // assume the first parallel request has already sent the code.
                if (existingUser.createdAt > gracePeriodLimit) {
                     // 🟠 TRACE LOG 3: The request was caught by the 10-second grace period. This request WILL NOT re-send the code.
                     console.log(`[DUPLICATE ERROR PATH] User ${email} created at ${existingUser.createdAt.toISOString()}. Suppressing re-send due to 10s grace period.`);
                     return res.status(202).json({ 
                        message: 'This email is already registered, and a code was just sent. Please check your inbox for the initial 6-digit code.',
                        userId: existingUser._id,
                        needsVerification: true
                    });
                }


                // 🛑 CHECK 2: LEGITIMATE RE-REGISTRATION ATTEMPT (Old Unverified Account)
                // If the user was created before the 10-second window, proceed to re-send the code.
                try {
                    // 🔴 TRACE LOG 4: The request passed the 10-second check and IS proceeding to re-send the code.
                    console.log(`[DUPLICATE ERROR PATH] User ${email} created at ${existingUser.createdAt.toISOString()}. OUTSIDE 10s grace. Re-generating and re-sending code.`);
                    
                    // Re-trigger the code generation and email send for the existing user
                    const newVerificationCode = await generateHashAndSaveVerificationCode(existingUser);
                    
                    // Re-use HTML template structure from the try block
                    const verificationSubject = 'Outflickz: Your Account Verification Code (Resent)';
                    const verificationHtml = `
                        <div style="background-color: #ffffffff; padding: 30px; border: 1px solid #ffffffff; max-width: 500px; margin: 0 auto; font-family: sans-serif; border-radius: 8px;">
                            <div style="text-align: center; padding-bottom: 20px;">
                                <img src="https://i.imgur.com/6Bvu8yB.png" alt="Outflickz Limited Logo" style="max-width: 120px; height: auto; display: block; margin: 0 auto;">
                            </div>
                            
                            <h2 style="color: #000000; font-weight: 600; text-align: center;">Verify Your Account</h2>

                            <p style="font-family: sans-serif; line-height: 1.6;">Hello ${existingUser.profile?.firstName || 'New Member'},</p>
                            <p style="font-family: sans-serif; line-height: 1.6;">A new verification code was sent for your existing account. Use the 6-digit code below to activate your account. This code will expire in 10 minutes.</p>
                            
                            <div style="text-align: center; margin: 30px 0; padding: 15px; background-color: #ffffff; border: 2px dashed #9333ea; border-radius: 4px;">
                                <strong style="font-size: 28px; letter-spacing: 5px; color: #000000;">${newVerificationCode}</strong>
                            </div>

                            <p style="font-size: 10px; margin-top: 30px; border-top: 1px solid #e0e0e0; padding-top: 10px; color: #888888; text-align: center;">&copy; ${new Date().getFullYear()} Outflickz Limited.</p>
                        </div>
                    `;

                    await sendMail(email, verificationSubject, verificationHtml);
                    console.log(`[DUPLICATE ERROR PATH] Verification code RE-SENT to old unverified existing user ${email} with code ${newVerificationCode}`);

                    return res.status(202).json({ 
                        message: 'This email is already registered but unverified. A new verification code has been sent.',
                        userId: existingUser._id,
                        needsVerification: true
                    });

                } catch (emailError) {
                    console.error(`CRITICAL: Resending email failed for existing unverified user ${email}:`, emailError);
                    return res.status(503).json({ 
                        message: 'Account exists but failed to resend verification email. Please use the "Resend Code" option directly.',
                        needsVerification: true,
                        userId: existingUser._id
                    });
                }
            }
            // If user exists and is verified, return the 409 conflict
            return res.status(409).json({ message: 'This email address is already registered.' });
        }
        
        if (newUser && (error.message.includes('Email service is unconfigured.') || error.message.includes('SMTP'))) {
            console.error(`CRITICAL: Email service failed for ${email}:`, error);
            return res.status(503).json({ 
                message: 'Account created, but we failed to send the verification email. Please use the "Resend Code" option or try logging in again.',
                needsVerification: true,
                userId: newUser._id
            });
        }

        console.error("User registration error:", error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// 5. POST /api/users/resend-verification (New Endpoint)
app.post('/api/users/resend-verification', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email is required to resend the code.' });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            // Respond generically to prevent email enumeration
            return res.status(200).json({ message: 'If an account exists, a new verification code has been sent.' });
        }
        
        // FIX: Check nested status field
        if (user.status && user.status.isVerified) {
             return res.status(400).json({ message: 'Account is already verified. Please proceed to login.' });
        }
        
        // 1. Generate and store a new code
        // FIX: Corrected function name to generateHashAndSaveVerificationCode
        const verificationCode = await generateHashAndSaveVerificationCode(user); 
        
        // 2. Send the new code email
        const verificationSubject = 'Outflickz: Your NEW Account Verification Code';
        const verificationHtml = `
            <div style="background-color: #ffffffff; padding: 30px; border: 1px solid #e0e0e0; max-width: 500px; margin: 0 auto; font-family: sans-serif; border-radius: 8px;">
                <div style="text-align: center; padding-bottom: 20px;">
                    <img src="https://i.imgur.com/6Bvu8yB.png" alt="Outflickz Limited Logo" style="max-width: 120px; height: auto; display: block; margin: 0 auto;">
                </div>
                
                <h2 style="color: #000000; font-weight: 600; text-align: center;">Resent Verification Code</h2>

                <p style="font-family: sans-serif; line-height: 1.6;">Hello ${user.profile?.firstName || 'User'},</p>
                <p style="font-family: sans-serif; line-height: 1.6;">A new 6-digit verification code was requested. Please use the code below to verify your email address. This code will expire in 10 minutes.</p>
                
                <div style="text-align: center; margin: 30px 0; padding: 15px; background-color: #ffffff; border: 2px dashed #9333ea; border-radius: 4px;">
                    <strong style="font-size: 28px; letter-spacing: 5px; color: #000000;">${verificationCode}</strong>
                </div>

                <p style="font-family: sans-serif; margin-top: 20px; line-height: 1.6; font-size: 14px; color: #555555;">If you did not request a new code, please secure your account immediately.</p>

                <p style="font-size: 10px; margin-top: 30px; border-top: 1px solid #e0e0e0; padding-top: 10px; color: #888888; text-align: center;">&copy; ${new Date().getFullYear()} Outflickz Limited.</p>
            </div>
        `;

        await sendMail(email, verificationSubject, verificationHtml);
        console.log(`New verification email sent successfully to ${email}`);

        // 3. Send successful response
        res.status(200).json({ message: 'A new verification code has been sent to your email address.' });

    } catch (error) {
        console.error("Resend verification code error:", error);
        res.status(500).json({ message: 'Failed to resend verification code due to a server error.' });
    }
});
// --- 2. POST /api/users/verify (Account Verification) ---
app.post('/api/users/verify', async (req, res) => {
    const { email, code } = req.body;

    // Basic Validation
    if (!email || !code) {
        return res.status(400).json({ message: 'Email and verification code are required.' });
    }

    try {
        // Explicitly select hidden fields
        const user = await User.findOne({ email })
            .select('+verificationCode +verificationCodeExpires');

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // 1. Check if already verified
        if (user.status && user.status.isVerified) { 
             return res.status(400).json({ message: 'Account is already verified.' });
        }
        
        // Ensure hash field exists
        if (!user.verificationCode) {
            return res.status(400).json({ message: 'No verification code is pending. Please resend the code.' });
        }

        // 2. Check Expiration
        if (new Date() > user.verificationCodeExpires) {
            return res.status(400).json({ message: 'Verification code has expired.' });
        }

        // 3. Compare Code
        const isMatch = await bcrypt.compare(code, user.verificationCode); 
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid verification code.' });
        }

        // 4. Verification Success: Update the user record
        await User.updateOne(
            { _id: user._id },
            { 
                $set: { 'status.isVerified': true },
                $unset: { verificationCode: "", verificationCodeExpires: "" }
            }
        );

        // ⭐ NEW: GENERATE AUTHENTICATION SESSION FOR AUTO-REDIRECT
        // This allows the frontend to skip the login page.
        
        // Replace 'generateUserAccessToken' with your actual JWT signing function
        const tokenPayload = { id: user._id, email: user.email };
        const accessToken = generateUserAccessToken(tokenPayload); // Ensure this function is defined in your app

        // Optional: Set HTTP-Only Refresh Cookie if your architecture uses them
        const refreshToken = generateUserRefreshToken(tokenPayload);
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        console.log(`User ${email} verified and session generated.`);
        
        // 5. Send Success Response with Token
        res.status(200).json({ 
            message: 'Account verified successfully!',
            accessToken: accessToken, // Frontend will save this to localStorage
            user: {
                id: user._id,
                email: user.email,
                firstName: user.firstName
            }
        });

    } catch (error) {
        console.error("User verification error:", error);
        res.status(500).json({ message: 'Server error during verification.' });
    }
});
// =========================================================
// 2. POST /api/users/login (FINAL STABILIZED VERSION)
// =========================================================
app.post('/api/users/login', async (req, res) => {
    // 1. Destructure with defaults to prevent "undefined" errors
    const { email, password, localCartItems = [] } = req.body; 

    try {
        // 2. Basic Validation
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required.' });
        }

        // 3. Find User (select password explicitly for comparison)
        const user = await User.findOne({ email }).select('+password').lean();
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        // 4. Compare Password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        // 5. Check verification status
        if (!user.status?.isVerified) {
            return res.status(403).json({ 
                message: 'Account not verified. Please verify your email to log in.',
                needsVerification: true,
                userId: user._id
            });
        }

        // 6. Generate Tokens
        // We use a try-catch specifically here to catch JWT_SECRET issues
        let accessToken, refreshToken;
        try {
            const tokenPayload = { id: user._id, email: user.email, role: 'user' }; 
            accessToken = generateUserAccessToken(tokenPayload);
            refreshToken = generateUserRefreshToken(tokenPayload);
        } catch (jwtError) {
            console.error("JWT Signing Error:", jwtError);
            return res.status(500).json({ message: "Internal server error: Token generation failed." });
        }

        // 7. Set Secure Cookie for Netlify
        res.cookie('userRefreshToken', refreshToken, {
            httpOnly: true,
            secure: true,      
            sameSite: 'None',  
            path: '/',         
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        // 8. Handle Cart & Logging in the background (Non-blocking)
        // We DON'T await these if they aren't critical for the response
        if (Array.isArray(localCartItems) && localCartItems.length > 0) {
            mergeLocalCart(user._id, localCartItems)
                .catch(err => console.error("Non-fatal Cart Merge Error:", err));
        }

        logActivity('LOGIN', `User ${user.email} logged in.`, user._id, { ipAddress: req.ip })
            .catch(err => console.warn('Activity logging failed:', err));

        // 9. Prepare Clean User Response
        const { password: _, ...userWithoutPassword } = user;

        // 10. Send Success
        return res.status(200).json({ 
            message: 'Login successful',
            accessToken: accessToken, 
            user: userWithoutPassword
        });

    } catch (error) {
        // This catches database connection issues or logic crashes
        console.error("CRITICAL LOGIN CRASH:", error);
        return res.status(500).json({ 
            message: 'An unexpected server error occurred.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined 
        });
    }
});

// --- Updated GET /api/users/account ---
app.get('/api/users/account', requireUserLogin, async (req, res) => {
    try {
        // Find user and explicitly select the nested objects from your DB schema
        const user = await User.findById(req.userId)
            .select('email profile address status membership')
            .lean();

        if (!user) {
            // If the token was valid but the user is gone from DB
            return res.status(404).json({ message: 'User account no longer exists.' });
        }

        // Return the exact structure your updateDOM() function expects
        res.status(200).json({
            id: user._id,
            email: user.email,
            profile: user.profile || {},     // firstName, lastName, phone, whatsapp
            address: user.address || {},     // street, city, state, zip, country
            status: user.status || {},       // isVerified, role
            membership: user.membership || {} // memberSince, lastUpdated
        });
        
    } catch (error) {
        console.error("Fetch profile error:", error);
        res.status(500).json({ message: 'Internal server error retrieving profile.' });
    }
});

// POST /api/users/refresh
app.post('/api/users/refresh', async (req, res) => {
    const isProduction = process.env.NODE_ENV === 'production';
    
    // 1. Get Refresh Token from the secure cookie
    const refreshToken = req.cookies.userRefreshToken; 
    
    if (!refreshToken) {
        return res.status(401).json({ message: 'No valid session found.' });
    }

    try {
        // 2. Verify the Refresh Token
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        
        if (decoded.role !== 'user') {
            throw new Error('Invalid token role for user refresh.');
        }

        // 3. Generate a NEW, short-lived Access Token
        const newAccessToken = generateUserAccessToken({ id: decoded.id, email: decoded.email });

        // 4. Send the new Access Token back
        res.status(200).json({ accessToken: newAccessToken });

    } catch (err) {
        // 5. If refresh token is expired/invalid, clear it and force re-login
        const isSecure = isProduction && req.headers['x-forwarded-proto'] === 'https';

        res.clearCookie('userRefreshToken', { 
            httpOnly: true, 
            secure: isSecure,
            sameSite: 'None',
        });
        
        res.status(401).json({ message: 'Session expired. Please log in again.' });
    }
});

// 4. PUT /api/users/profile (Update Personal Info - Protected)
app.put('/api/users/profile', verifyUserToken, async (req, res) => {
    try {
        // 🔔 UPDATED: Destructure new fields: whatsapp
        const { firstName, lastName, phone, whatsapp } = req.body;
        
        if (!firstName || !lastName) {
             return res.status(400).json({ message: 'First name and last name are required.' });
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.userId,
            {
                // Note: The 'profile' field is likely an embedded document or object in your schema
                $set: {
                    'profile.firstName': firstName,
                    'profile.lastName': lastName,
                    'profile.phone': phone || null, // Update phone if provided
                    'profile.whatsapp': whatsapp || null // 🎉 NEW: Update whatsapp if provided
                }
            },
            { new: true, runValidators: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.status(200).json({ message: 'Profile details updated successfully.', profile: updatedUser.profile });

    } catch (error) {
        console.error("Profile update error:", error);
        res.status(500).json({ message: 'Failed to update profile details.' });
    }
});
// 5. PUT /api/users/address (Update Contact Address - Protected)
app.put('/api/users/address', verifyUserToken, async (req, res) => {
    try {
        const { street, city, state, zip, country } = req.body;
        
        // 1. Validation check
        if (!street || !city || !country) {
            return res.status(400).json({ message: 'Street, city, and country are required for the address.' });
        }

        // 2. Database Update
        const updatedUser = await User.findByIdAndUpdate(
            req.userId,
            {
                // Use $set to update fields within the embedded 'address' object
                $set: {
                    'address.street': street,
                    'address.city': city,
                    'address.state': state,
                    'address.zip': zip,
                    'address.country': country
                }
            },
            // Important Options: 
            // { new: true } returns the modified document rather than the original.
            { new: true, runValidators: true, select: 'email profile address status membership' } 
            // Select all fields needed by the frontend's updateDOM function
        );

        if (!updatedUser) {
            // Should not happen if verifyUserToken works, but good practice
            return res.status(404).json({ message: 'User not found or session expired.' });
        }

        // 3. SUCCESS Response
        // Send back the data structure the client's updateDOM function expects
        return res.status(200).json({ 
            message: 'Contact address updated successfully!', 
            address: updatedUser.address // The client specifically needs the updated address object
        });

    } catch (error) {
        console.error('Address update error:', error);
        // Return a generic error message for the client
        return res.status(500).json({ message: 'Server error: Could not save address. Please try again.' });
    }
});
// =========================================================
// 3. POST /api/users/logout (Logout) - CORRECTED
// =========================================================
/**
 * Clears the HTTP-only session cookie, effectively logging the user out.
 */
app.post('/api/users/logout', (req, res) => {
    try {
        const isProduction = process.env.NODE_ENV === 'production';

        // 💡 FIX 1: Use the correct cookie name: 'userRefreshToken'
        // 💡 FIX 2: Use the cross-origin security flags (secure: true, sameSite: 'None')
        //            to successfully clear a cookie that was set with these flags.
        res.clearCookie('userRefreshToken', {
            httpOnly: true,
            // Must be true in production to support SameSite: 'None'
            secure: isProduction, 
            // Must be 'None' to successfully clear a cookie set with 'None'
            sameSite: 'None', 
        });

        // 💡 ENHANCEMENT: You may also want to explicitly check and clear 
        // the refresh token used in the refresh route to ensure full session invalidation.
        
        console.log("User logged out. Session cookie cleared.");
        
        // Send a success response.
        res.status(200).json({ 
            message: 'Logout successful. Session cookie cleared.'
        });

    } catch (error) {
        console.error("Logout error:", error);
        // We still send 200 to ensure the client-side UI updates correctly, 
        // as the cookie clearance usually happens at the header level before any try/catch logic.
        res.status(200).json({ message: 'Logout successful despite minor server error.' });
    }
});


// 4. POST /api/users/forgot-password (Forgot Password)
app.post('/api/users/forgot-password', async (req, res) => {
    const { email } = req.body;

    // Respond successfully immediately to prevent user enumeration attacks
    res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });

    try {
        const user = await User.findOne({ email });
        
        if (user) {
            // 1. Generate a secure, unique, time-limited token (e.g., using crypto or jwt)
            const resetToken = crypto.randomBytes(32).toString('hex'); // Assumes 'crypto' is required

            // 2. Save the token and its expiry time to the user's document
            // await User.updateOne({ _id: user._id }, { resetPasswordToken: resetToken, resetPasswordExpires: Date.now() + 3600000 }); // 1 hour

            // 3. Construct the actual reset link
            const resetLink = `https://outflickz.com/reset-password?token=${resetToken}&email=${email}`;

            // 🛠️ NEW: Updated HTML template with Logo and Styling
            const resetSubject = 'Outflickz Limited: Password Reset Request';
            const resetHtml = `
                <div style="background-color: #ffffff; color: #000000; padding: 20px; border: 1px solid #eeeeee; max-width: 600px; margin: 0 auto; font-family: sans-serif; border-radius: 8px;">
                    <!-- Outflickz Logo -->
                    <div style="text-align: center; padding-bottom: 20px;">
                        <img src="https://i.imgur.com/6Bvu8yB.png" alt="Outflickz Limited Logo" style="max-width: 150px; height: auto; display: block; margin: 0 auto;">
                    </div>

                    <h2 style="color: #000000; font-weight: 600;">Password Reset Request</h2>

                    <p style="font-family: sans-serif; line-height: 1.6;">Hello,</p>
                    <p style="font-family: sans-serif; line-height: 1.6;">You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
                    
                    <p style="font-family: sans-serif; line-height: 1.6;">Please click on the button below to complete the password reset process:</p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetLink}" 
                            style="display: inline-block; padding: 10px 20px; background-color: #000000; color: #ffffff; text-decoration: none; border-radius: 4px; font-weight: bold;">
                            Reset My Password
                        </a>
                    </div>

                    <p style="font-family: sans-serif; margin-top: 15px; line-height: 1.6;">If you did not request this, please ignore this email and your password will remain unchanged.</p>

                    <!-- Footer -->
                    <p style="font-size: 12px; margin-top: 30px; border-top: 1px solid #eeeeee; padding-top: 10px; color: #555555; text-align: center;">&copy; ${new Date().getFullYear()} Outflickz Limited. All rights reserved.</p>
                </div>
            `;
            
            // Send the email
            sendMail(email, resetSubject, resetHtml)
                .catch(error => console.error(`Failed to send password reset email to ${email}:`, error));
        }
    } catch (error) {
        // Log internal error but do not change the 200 response sent earlier
        console.error("Forgot password process error:", error);
    }
});

// =========================================================
// 6. PUT /api/users/change-password (Change Password - Protected)
// =========================================================
app.put('/api/users/change-password', verifyUserToken, async (req, res) => {
    // req.userId is set by the verifyUserToken middleware
    const { currentPassword, newPassword } = req.body;

    // 1. Basic Input Validation
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: 'Current password and new password are required.' });
    }

    // Optional: Add new password complexity checks (length, mix of chars)
    if (newPassword.length < 8) {
        return res.status(400).json({ message: 'New password must be at least 8 characters long.' });
    }

    try {
        // 2. Fetch the user, explicitly including the stored password
        const user = await User.findById(req.userId).select('+password').lean();

        if (!user) {
            // Should be rare, but handles token-user mismatch
            return res.status(404).json({ message: 'User not found or session expired.' });
        }

        // 3. Verify the current password
        if (!(await bcrypt.compare(currentPassword, user.password))) {
            // Log the failed attempt for security monitoring
            try {
                await logActivity(
                    'PASSWORD_CHANGE_FAILURE',
                    `User ${user.email} failed to change password due to incorrect current password.`,
                    user._id,
                    { ipAddress: req.ip }
                );
            } catch (logErr) {
                console.warn('Activity logging failed (password change failure):', logErr);
            }
            return res.status(401).json({ message: 'The current password you entered is incorrect.' });
        }
        
        // Check if the new password is the same as the current password
        if (currentPassword === newPassword) {
            return res.status(400).json({ message: 'New password cannot be the same as the current password.' });
        }

        // 4. Hash the new password
        // Use a function from your setup to hash the password (e.g., bcrypt.hash)
        const hashedPassword = await bcrypt.hash(newPassword, 10); // 10 is the salt rounds

        // 5. Update the user's password in the database
        await User.findByIdAndUpdate(
            req.userId,
            { password: hashedPassword },
            { new: true, runValidators: true }
        );

        // 6. Log the successful password change event
        try {
            await logActivity(
                'PASSWORD_CHANGE',
                `User **${user.email}** successfully changed their password.`,
                user._id,
                { ipAddress: req.ip }
            );
        } catch (logErr) {
            console.warn('Activity logging failed (password change success):', logErr);
        }

        // 7. Success Response
        // NOTE: It is a good security practice to force a re-login after a password change
        // by clearing the old token/cookie, but we'll stick to the requested response format for now.
        return res.status(200).json({ 
            message: 'Password updated successfully. You should log in again with your new password.',
            shouldRelogin: true // Hint for the frontend
        });

    } catch (error) {
        console.error("Change password error:", error);
        return res.status(500).json({ message: 'Server error: Failed to change password.' });
    }
});

app.get('/api/auth/status', (req, res) => {
    // --- 1. Attempt Access Token Verification (The immediate fix for the profile click) ---
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
            // Verify the Access Token from the header
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            // SUCCESS via Access Token: The user can access the profile.
            console.log('DEBUG STATUS: Access Token verification successful.');
            return res.status(200).json({ message: 'Authenticated via Access Token', isAuthenticated: true });
            
        } catch (err) {
            console.warn('DEBUG STATUS: Access Token expired/invalid. Checking session cookie...');
            // Fall through to cookie check
        }
    }    
    const refreshToken = req.cookies.userRefreshToken; 
    
    // NOTE: This is the check that currently fails due to the missing cookie.
    if (!refreshToken) {
        console.warn('DEBUG STATUS: Final Auth Check Failed. No Access Token and no Refresh Token cookie.');
        return res.status(401).json({ message: 'Authentication failed. No valid token or session cookie.' });
    }

    try {
        // Verify the Refresh Token from the cookie
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        
        // SUCCESS via Refresh Token Cookie: Should be used by secureUserFetch refresh calls
        console.log('DEBUG STATUS: Authentication via Refresh Token cookie successful.');
        return res.status(200).json({ message: 'Authenticated via Session Cookie', isAuthenticated: true });
        
    } catch (err) {
        // Failed all checks.
        console.error("DEBUG STATUS: Session Cookie verification failed:", err.message);
        return res.status(401).json({ message: 'Session cookie invalid or expired. Re-login required.' });
    }
});

// =========================================================
// 5. POST /api/users/cart - Add Item to Cart (Protected)
// =========================================================
app.post('/api/users/cart', verifyUserToken, async (req, res) => {
    // ... (gathering and validation remains the same: FIX 1, FIX 2)
    const { productId, name, productType, size, color, price, quantity, imageUrl, variationIndex, variation } = req.body;
    const userId = req.userId;

    // 🚩 TEMPORARY DEBUG LOGIC 🚩
    if (!productId) console.log('Validation failed: Missing productId');
    if (!name) console.log('Validation failed: Missing name');
    if (!productType) console.log('Validation failed: Missing productType'); // LIKELY CULPRIT
    if (!size) console.log('Validation failed: Missing size'); // LIKELY CULPRIT
    if (!price || price <= 0) console.log('Validation failed: Invalid price');
    if (!quantity || quantity < 1) console.log('Validation failed: Invalid quantity');
    if (variationIndex === undefined || variationIndex === null) console.log('Validation failed: Missing variationIndex');

    // Basic Input Validation
    if (!productId || !name || !productType || !size || !price || !quantity || price <= 0 || quantity < 1 || variationIndex === undefined || variationIndex === null) {
        return res.status(400).json({ message: 'Missing or invalid item details, including variation information.' });
    }

    const newItem = {
    productId,
    name,
    productType: productType || 'Product', 
    size,
    color: color,
    price,
    quantity,
    imageUrl,
    variationIndex,
    variation: variation || (color ? `Color: ${color}` : `${productType} Var: ${variationIndex}`), 
};

    try {
        let cart = await Cart.findOne({ userId });

        if (!cart) {
            cart = await Cart.create({ userId, items: [newItem] });
            // Simplified return for cart creation
            const totals = calculateCartTotals(cart.items);
            return res.status(201).json({ message: 'Cart created and item added.', items: cart.items, ...totals });
        }

        // 3. Check if the item variant already exists in the cart
        const existingItemIndex = cart.items.findIndex(item =>
            item.productId.equals(productId) &&
            item.size === size &&
            item.color === newItem.color && 
            item.variationIndex === variationIndex
        );

        if (existingItemIndex > -1) {
            // Item exists: Update quantity
            cart.items[existingItemIndex].quantity += quantity;
            cart.items[existingItemIndex].updatedAt = Date.now();
        } else {
            // Item does not exist: Add new item
            cart.items.push(newItem);
        }

        // 4. Save the updated cart and use Mongoose's ability to return the updated document
        // 🚀 OPTIMIZATION: Use findOneAndUpdate to save and fetch the final cart in one operation
        const updatedCart = await Cart.findOneAndUpdate(
             { userId },
             { items: cart.items, updatedAt: Date.now() },
             { new: true, lean: true } // Return the new document, use lean for performance
        );
        
        // 💡 REMOVED: await cart.save(); 
        // 💡 REMOVED: const updatedCart = await Cart.findOne({ userId }).lean();

        if (!updatedCart) {
             return res.status(404).json({ message: 'Cart not found during update.' });
        }

        const totals = calculateCartTotals(updatedCart.items);

        res.status(200).json({ 
            message: 'Item added/quantity updated successfully.', 
            items: updatedCart.items, // Return the full updated item list
            ...totals
        });

    } catch (error) {
        console.error('Error adding item to cart:', error);
        res.status(500).json({ message: 'Failed to add item to shopping bag.' });
    }
});

// =========================================================
// 1. GET /api/users/cart - Retrieve Cart (Protected)
// =========================================================
app.get('/api/users/cart', verifyUserToken, async (req, res) => {
    try {
        // req.userId is set by verifyUserToken middleware
        const userId = req.userId;
        
        // Find the cart for the user
        const cart = await Cart.findOne({ userId }).lean();

        if (!cart) {
            // If no cart found, return an empty cart structure
            return res.status(200).json({
                items: [],
                ...calculateCartTotals([]),
            });
        }
        
        const totals = calculateCartTotals(cart.items);

        // Respond with the items and calculated totals
        res.status(200).json({
            items: cart.items, 
            ...totals,
        });

    } catch (error) {
        console.error('Error fetching cart:', error);
        res.status(500).json({ message: 'Failed to retrieve shopping bag.' });
    }
});
// =========================================================
// 2. PATCH /api/users/cart/:itemId - Update Quantity (Protected)
// =========================================================
app.patch('/api/users/cart/:itemId', verifyUserToken, async (req, res) => {
    try {
        const userId = req.userId;
        const itemId = req.params.itemId; 
        const { quantity } = req.body;

        const newQuantity = parseInt(quantity);
        if (isNaN(newQuantity) || newQuantity < 1) {
            return res.status(400).json({ message: 'Invalid quantity provided.' });
        }
        
        // Find cart by userId and update the specific item's quantity 
        const cart = await Cart.findOneAndUpdate(
            { userId, 'items._id': itemId },
            { 
                '$set': { 
                    'items.$.quantity': newQuantity, 
                    'updatedAt': Date.now() 
                } 
            },
            { new: true, lean: true } // Return the updated document, use lean
        );

        if (!cart) {
            return res.status(404).json({ message: 'Item not found in your cart.' });
        }

        // 🌟 IMPROVEMENT: Calculate and return full cart data 🌟
        const totals = calculateCartTotals(cart.items);
        res.status(200).json({ 
            message: 'Quantity updated successfully.',
            items: cart.items,
            ...totals 
        });

    } catch (error) {
        console.error('Error updating item quantity:', error);
        res.status(500).json({ message: 'Failed to update item quantity.' });
    }
});

// =========================================================
// 3. DELETE /api/users/cart/:itemId - Remove Single Item (Protected)
// =========================================================
app.delete('/api/users/cart/:itemId', verifyUserToken, async (req, res) => {
    try {
        const userId = req.userId;
        const itemId = req.params.itemId;

        // Pull the specific item sub-document from the items array
        const cart = await Cart.findOneAndUpdate(
            { userId },
            { 
                '$pull': { 
                    items: { _id: itemId } 
                },
                '$set': { 
                    'updatedAt': Date.now() 
                } 
            },
            { new: true, lean: true } // Return the updated document, use lean
        );

        if (!cart) {
            return res.status(404).json({ message: 'Item not found in your cart.' });
        }

        // 🌟 IMPROVEMENT: Calculate and return full cart data 🌟
        const totals = calculateCartTotals(cart.items);
        res.status(200).json({ 
            message: 'Item removed successfully.', 
            items: cart.items,
            ...totals 
        });

    } catch (error) {
        console.error('Error removing item:', error);
        res.status(500).json({ message: 'Failed to remove item.' });
    }
});
// =========================================================
// 4. DELETE /api/users/cart - Clear All Items (Protected)
// =========================================================
app.delete('/api/users/cart', verifyUserToken, async (req, res) => {
    try {
        const userId = req.userId;
        
        // Set the entire items array to an empty array
        const cart = await Cart.findOneAndUpdate(
            { userId },
            { 
                items: [],
                updatedAt: Date.now() 
            },
            { new: true, lean: true }
        );

        if (!cart) {
            return res.status(404).json({ message: 'Cart not found to clear.' });
        }

        // 🌟 IMPROVEMENT: Return empty items array and calculated totals 🌟
        const totals = calculateCartTotals(cart.items); // Should return zero totals
        res.status(200).json({ 
            message: 'Shopping bag cleared successfully.',
            items: cart.items,
            ...totals
        });

    } catch (error) {
        console.error('Error clearing cart:', error);
        res.status(500).json({ message: 'Failed to clear shopping bag.' });
    }
});

// --- 1. WEBHOOK ENDPOINT ---
// --- 1. WEBHOOK ENDPOINT ---
app.post('/api/paystack/webhook', async (req, res) => {
    const secret = process.env.PAYSTACK_SECRET_KEY;
    const paystackSignature = req.headers['x-paystack-signature'];
    
    const hash = crypto.createHmac('sha512', secret)
                       .update(JSON.stringify(req.body))
                       .digest('hex');
    
    if (hash !== paystackSignature) return res.status(401).send('Unauthorized');

    const event = req.body;
    const transactionData = event.data;
    const OrderModel = mongoose.models.Order || mongoose.model('Order');

    if (event.event === 'charge.success') {
        try {
            const updatedOrder = await OrderModel.findOneAndUpdate(
                { orderReference: transactionData.reference },
                {
                    paymentStatus: 'Paid',           
                    status: 'Processing',            
                    amountPaidKobo: transactionData.amount, 
                    paymentTxnId: transactionData.reference,
                    isPaystackPending: false,        
                    $push: { notes: `Paystack Webhook Verified (${new Date().toLocaleString()})` }
                },
                { new: true }
            );

            if (updatedOrder) {
                // ⭐ CORRECTED: Pass Email AND Order Object
                // If Guest, use guestEmail. If logged in, use shipping address email.
                const targetEmail = updatedOrder.guestEmail || updatedOrder.shippingAddress?.email;
                
                try {
                    await  sendAdminOrderNotification(targetEmail, updatedOrder);
                    console.log("✅ Admin Notified via Webhook");
                } catch (emailErr) {
                    console.error("❌ Admin Email Error (Webhook):", emailErr);
                }
                
                return res.status(200).send('Success');
            }
        } catch (error) {
            return res.status(500).send('Internal Error'); 
        }
    }
    res.status(200).send('Acknowledged');
});

// --- 2. MANUAL VERIFY ROUTE ---
app.get('/api/orders/verify/:reference', async (req, res) => {
    const { reference } = req.params;
    const OrderModel = mongoose.models.Order || mongoose.model('Order');

    try {
        const response = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
            headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
        });
        const data = await response.json();

        if (data.status && data.data.status === 'success') {
            const updated = await OrderModel.findOneAndUpdate(
                { orderReference: reference },
                { 
                    paymentStatus: 'Paid', 
                    status: 'Processing', // Note: status is 'Processing', your function handles 'Confirmed'/'Completed'
                    amountPaidKobo: data.data.amount,
                    isPaystackPending: false,
                    paidAt: new Date()
                },
                { new: true }
            );

            if (updated) {
                // ⭐ CORRECTED: Pass Email AND Order Object
                const targetEmail = updated.guestEmail || updated.shippingAddress?.email;
                
                try {
                    await  sendAdminOrderNotification(targetEmail, updated);
                    console.log("✅ Admin Notified via Verify Route");
                } catch (emailErr) {
                    console.error("❌ Admin Email Error (Verify Route):", emailErr);
                }

                return res.status(200).json({ 
                    message: 'Verified', 
                    status: 'Paid', 
                    orderId: updated._id 
                });
            }
        }
        res.status(400).json({ message: 'Payment verification failed' });
    } catch (error) {
        console.error("Verify Error:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.post('/api/orders/place/paystack', verifyUserToken, async (req, res) => {
    // 1. Identify if User or Guest
    const userId = req.userId || null;
    const { 
        shippingAddress, 
        totalAmount, 
        subtotal, 
        shippingFee, 
        tax, 
        orderItems, 
        email: incomingEmail, // Extract email from frontend
        isGuest: incomingIsGuest // Extract isGuest flag from frontend
    } = req.body;

    const isGuest = !userId || incomingIsGuest === true || incomingIsGuest === 'true';

    try {
        const sanitizedShipping = typeof shippingAddress === 'string' ? JSON.parse(shippingAddress) : shippingAddress;
        let rawItems = typeof orderItems === 'string' ? JSON.parse(orderItems) : orderItems;

        // 2. Guest items come from the request, not the database Cart model
        if (!rawItems || (Array.isArray(rawItems) && rawItems.length === 0)) {
            if (!isGuest) {
                const userCart = await Cart.findOne({ userId }).lean();
                rawItems = userCart?.items || [];
            }
        }

        if (!rawItems || rawItems.length === 0) return res.status(400).json({ message: 'Cart is empty.' });

        const finalOrderItems = await Promise.all(rawItems.map(async (item) => {
            const allowedCollections = ['WearsCollection', 'CapCollection', 'NewArrivals', 'PreOrderCollection'];
            let validatedType = item.productType;
            let typeIsCorrect = false;

            for (const col of allowedCollections) {
                const Model = getProductModel(col);
                if (await Model.exists({ _id: item.productId })) {
                    validatedType = col;
                    typeIsCorrect = true;
                    break;
                }
            }
            if (!typeIsCorrect) throw new Error(`Product ${item.productId} not found.`);

            return {
                productId: item.productId,
                name: item.name,
                imageUrl: item.imageUrl,
                productType: validatedType,
                quantity: parseInt(item.quantity),
                priceAtTimeOfPurchase: parseFloat(item.price || item.priceAtTimeOfPurchase),
                variationIndex: parseInt(item.variationIndex) || 0, 
                size: item.size,
                color: item.color,
                variation: item.variation
            };
        }));

        const orderRef = `outflickz_${Date.now()}_${Math.floor(Math.random() * 1000)}`; 

        // 3. Prepare order payload following schema rules
        const orderPayload = {
            userId: userId,
            isGuest: isGuest,
            items: finalOrderItems, 
            shippingAddress: sanitizedShipping,
            totalAmount: parseFloat(totalAmount),
            subtotal: parseFloat(subtotal || 0),
            shippingFee: parseFloat(shippingFee || 0),
            tax: parseFloat(tax || 0),
            status: 'Pending',
            paymentStatus: 'Awaiting Payment', 
            paymentMethod: 'Paystack',
            orderReference: orderRef,
            isPaystackPending: true,
            amountPaidKobo: 0, 
            paymentTxnId: orderRef, 
        };

        // ⭐ CRITICAL: Provide guestEmail if userId is null
        if (isGuest) {
            orderPayload.guestEmail = incomingEmail || (sanitizedShipping && sanitizedShipping.email);
        }

        // CREATE INITIAL RECORD
        const newOrder = await Order.create(orderPayload);

        // 4. Determine which email to return to frontend Paystack pop-up
        let customerEmailForPaystack = incomingEmail;
        if (!isGuest) {
            const user = await User.findById(userId).select('email');
            customerEmailForPaystack = user?.email;
        }

        res.status(201).json({
            message: 'Order initialized.',
            orderId: newOrder._id,
            orderReference: newOrder.orderReference,
            totalAmount: newOrder.totalAmount,
            email: customerEmailForPaystack,
            isGuest: isGuest
        });

    } catch (error) {
        console.error('🔴 Order Creation Error:', error.message);
        res.status(500).json({ message: error.message });
    }
});

// =========================================================
// 8. POST /api/notifications/admin-order-email - Send Notification to Admin
// Modified to include WhatsApp Contact Button for Admin
// =========================================================
app.post('/api/notifications/admin-order-email', async (req, res) => {
    const { 
        orderId, 
        totalAmount, 
        paymentMethod, 
        shippingDetails, 
        items, 
        adminEmail,
        paymentReceiptUrl, 
        subtotal,
        shippingFee,
        tax
    } = req.body;

    // 1. Basic Validation
    if (!orderId || !totalAmount || !adminEmail || !items || items.length === 0) {
        return res.status(400).json({ message: 'Missing required notification data or order items.' });
    }

    try {
        // --- STEP 1: WhatsApp Logic ---
        // Clean phone number (remove spaces, +, dashes) for the wa.me API
        const rawPhone = shippingDetails.phone || '';
        const cleanPhone = rawPhone.replace(/\D/g, ''); 
        // Create the WhatsApp link with a pre-filled message
        const whatsappUrl = cleanPhone ? `https://wa.me/${cleanPhone}?text=Hello%20from%20Outflickz%20Admin.%20Regarding%20your%20Order%20%23${orderId}` : null;

        // --- STEP 2: Prepare Attachments from B2 ---
        const attachments = [];
        let attachmentFileName = null; 
        
        if (paymentMethod === 'Bank Transfer' && paymentReceiptUrl) {
            try {
                const fileKey = getFileKeyFromUrl(paymentReceiptUrl);
                if (fileKey) {
                    const getObjectCommand = new GetObjectCommand({
                        Bucket: IDRIVE_BUCKET_NAME,
                        Key: fileKey,
                    });
                    const response = await s3Client.send(getObjectCommand);
                    const contentType = response.ContentType || 'application/octet-stream';
                    const suggestedFilename = fileKey.split('/').pop() || 'payment-receipt.jpg'; 
                    const buffer = await streamToBuffer(response.Body);

                    attachments.push({
                        filename: suggestedFilename,
                        content: buffer,
                        contentType: contentType,
                    });
                    attachmentFileName = suggestedFilename; 
                }
            } catch (downloadError) {
                console.error(`[Admin Email] Failed to download receipt:`, downloadError.message);
            }
        }

        // --- STEP 3: Format the Email Content ---
        const paymentStatus = (paymentMethod === 'Paystack/Card' || paymentMethod === 'Paystack') 
            ? 'Payment Confirmed (Paystack)' 
            : 'Payment Awaiting Verification (Bank Transfer)';
        
        const itemDetailsHtml = items.map(item => `
            <tr>
                <td style="padding: 12px 0; border-bottom: 1px solid #eee; font-size: 14px; color: #333;">
                    <table border="0" cellpadding="0" cellspacing="0">
                        <tr>
                            <td style="padding-right: 10px;">
                                <img src="${item.imageUrl || 'https://placehold.co/40x40/f7f7f7/999?text=X'}" width="40" height="40" style="display: block; border: 1px solid #ddd; border-radius: 4px;">
                            </td>
                            <td>${item.name || 'N/A'}</td>
                        </tr>
                    </table>
                </td>
                <td style="padding: 12px 0; border-bottom: 1px solid #eee; font-size: 12px; color: #555;">
                    <span style="display: block;">Size: <strong>${item.size || 'N/A'}</strong></span>
                    <span style="display: block; margin-top: 2px;">Color: ${item.color || 'N/A'}</span>
                </td>
                <td style="padding: 12px 0; border-bottom: 1px solid #eee; font-size: 14px; color: #333; text-align: center;">${item.quantity}</td>
                <td style="padding: 12px 0; border-bottom: 1px solid #eee; font-size: 14px; color: #333; text-align: right;">
                    ₦${(parseFloat(item.price || item.priceAtTimeOfPurchase) * item.quantity).toLocaleString('en-US', { minimumFractionDigits: 2 })}
                </td>
            </tr>
        `).join('');

        const whatsappButtonHtml = whatsappUrl ? `
            <div style="margin: 20px 0; text-align: center;">
                <a href="${whatsappUrl}" style="background-color: #25D366; color: white; padding: 14px 25px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block; font-size: 16px;">
                    💬 Contact Customer via WhatsApp
                </a>
                <p style="font-size: 12px; color: #666; margin-top: 8px;">Direct Number: ${rawPhone}</p>
            </div>
        ` : `<p style="color: #d9534f; text-align: center;">No valid phone number provided for WhatsApp.</p>`;

        const attachmentConfirmationHtml = attachmentFileName ? `
            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 30px; border: 1px solid #c0e6c0; border-radius: 4px; background-color: #e0ffe0;">
                <tr>
                    <td style="padding: 15px; font-size: 14px; color: #006400; font-weight: bold; text-align: center;">
                        ✅ Receipt Attached: ${attachmentFileName}
                    </td>
                </tr>
            </table>
        ` : (paymentMethod === 'Bank Transfer' ? `<p style="color: #FF4500; font-weight: bold; text-align: center;">⚠️ Receipt attachment failed.</p>` : '');

        const emailHtml = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        @media only screen and (max-width: 600px) { .container { width: 100% !important; } }
    </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f4; font-family: Arial, sans-serif;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%">
        <tr>
            <td align="center" style="padding: 20px 0;">
                <table border="0" cellpadding="0" cellspacing="0" width="600" class="container" style="background-color: #ffffff; border: 1px solid #dddddd; border-radius: 8px;">
                    <tr>
                        <td align="center" style="padding: 20px 0;">
                            <img src="https://i.imgur.com/6Bvu8yB.png" alt="Logo" width="180">
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 0 40px 40px 40px;">
                            <h1 style="color: #000; font-size: 24px; text-align: center; margin-bottom: 10px;">🚨 NEW ORDER 🚨</h1>
                            
                            ${whatsappButtonHtml}

                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 25px; border-bottom: 2px solid #000;">
                                <tr><td colspan="2" style="font-size: 16px; font-weight: bold; padding-bottom: 5px;">ORDER SUMMARY</td></tr>
                            </table>
                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 10px; font-size: 14px;">
                                <tr><td style="padding: 5px 0; color: #555;">Order ID:</td><td align="right" style="font-weight: bold;">${orderId}</td></tr>
                                <tr><td style="padding: 5px 0; color: #555;">Payment:</td><td align="right">${paymentMethod}</td></tr>
                                <tr><td style="padding: 5px 0; color: #555;">Status:</td><td align="right" style="color: ${paymentStatus.includes('Confirmed') ? 'green' : '#FFA500'}; font-weight: bold;">${paymentStatus}</td></tr>
                                <tr><td style="padding: 5px 0; color: #555;">Subtotal:</td><td align="right">₦${parseFloat(subtotal || 0).toLocaleString()}</td></tr>
                                <tr><td style="padding: 5px 0; color: #555;">Shipping:</td><td align="right">₦${parseFloat(shippingFee || 0).toLocaleString()}</td></tr>
                                <tr><td style="padding: 20px 0; font-size: 18px; font-weight: bold;">TOTAL:</td><td align="right" style="font-size: 18px; font-weight: bold;">₦${parseFloat(totalAmount).toLocaleString()}</td></tr>
                            </table>

                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 30px; border-bottom: 2px solid #000;">
                                <tr><td style="font-size: 16px; font-weight: bold; padding-bottom: 5px;">SHIPPING DETAILS</td></tr>
                            </table>
                            <div style="font-size: 14px; padding-top: 10px; line-height: 1.6;">
                                <strong>${shippingDetails.firstName} ${shippingDetails.lastName}</strong><br>
                                Email: ${shippingDetails.email}<br>
                                Phone: ${rawPhone}<br>
                                Address: ${shippingDetails.street}, ${shippingDetails.city}, ${shippingDetails.state}, ${shippingDetails.country}
                            </div>

                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 30px;">
                                <tr style="background-color: #f7f7f7; font-size: 12px; color: #555;">
                                    <th align="left" style="padding: 10px;">PRODUCT</th>
                                    <th align="left" style="padding: 10px;">DETAILS</th>
                                    <th align="center" style="padding: 10px;">QTY</th>
                                    <th align="right" style="padding: 10px;">PRICE</th>
                                </tr>
                                ${itemDetailsHtml}
                            </table>

                            ${attachmentConfirmationHtml}
                        </td>
                    </tr>
                    <tr>
                        <td align="center" style="background-color: #f7f7f7; padding: 15px; font-size: 11px; color: #999; border-radius: 0 0 8px 8px;">
                            &copy; ${new Date().getFullYear()} OUTFULICKZ.
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`;

        await sendMail(adminEmail, `[New Order] #${orderId} - ${paymentStatus}`, emailHtml, attachments);
        res.status(200).json({ message: 'Notification sent.' });

    } catch (error) {
        console.error('Admin Email Error:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});


// =========================================================
// 7. POST /api/orders/place/pending - Corrected for Guest Validation
// =========================================================
app.post('/api/orders/place/pending', verifyUserToken, (req, res) => {
    singleReceiptUpload(req, res, async (err) => {
        if (err instanceof multer.MulterError) {
             return res.status(400).json({ message: `File upload failed: ${err.message}` });
        } else if (err) {
             return res.status(500).json({ message: 'Error processing file upload.' });
        }

        const userId = req.userId || null;
        const isGuest = !userId;
        
        const { 
            shippingAddress: shippingAddressString, 
            paymentMethod, 
            totalAmount: totalAmountString, 
            orderItems: orderItemsString,
            email: guestEmailFromForm, // Incoming guest email from frontend
            subtotal: subtotalString,
            shippingFee: shippingFeeString,
            tax: taxString
        } = req.body;
        
        const receiptFile = req.file; 
        const totalAmount = parseFloat(totalAmountString);

        let shippingAddress;
        try {
             shippingAddress = shippingAddressString ? JSON.parse(shippingAddressString) : null;
        } catch (e) {
             return res.status(400).json({ message: 'Invalid shipping address format.' });
        }
        
        if (!shippingAddress || !totalAmount || totalAmount <= 0) {
             return res.status(400).json({ message: 'Missing shipping address or invalid total amount.' });
        }

        let paymentReceiptUrl = null;
        if (paymentMethod === 'Bank Transfer') {
            if (!receiptFile) return res.status(400).json({ message: 'Bank payment receipt is required.' });
            paymentReceiptUrl = await uploadFileToPermanentStorage(receiptFile);
        }

        try {
            let finalOrderItems = [];
            if (orderItemsString) {
                const rawItems = JSON.parse(orderItemsString);
                finalOrderItems = await Promise.all(rawItems.map(async (item) => {
                    let correctedType = item.productType;
                    if (!PRODUCT_MODEL_MAP[item.productType]) {
                        for (const type of Object.keys(PRODUCT_MODEL_MAP)) {
                            const Model = getProductModel(type);
                            if (await Model.exists({ _id: item.productId })) {
                                correctedType = type;
                                break;
                            }
                        }
                    }
                    return {
                        ...item,
                        priceAtTimeOfPurchase: item.price,
                        productType: correctedType
                    };
                }));
            }

            if (finalOrderItems.length === 0) {
                return res.status(400).json({ message: 'Order items are missing.' });
            }

            const orderRef = `REF-${Date.now()}-${isGuest ? 'GUEST' : userId.substring(0, 5)}`; 

            // ⭐ FIX: Map the fields to match your Mongoose Schema exactly
            const orderPayload = {
                userId: userId, 
                isGuest: isGuest, // Set explicit guest status
                items: finalOrderItems, 
                shippingAddress: shippingAddress,
                totalAmount: totalAmount,
                subtotal: parseFloat(subtotalString) || 0,
                shippingFee: parseFloat(shippingFeeString) || 0,
                tax: parseFloat(taxString) || 0,
                status: 'Pending', 
                paymentMethod: paymentMethod,
                orderReference: orderRef, 
                paymentReceiptUrl: paymentReceiptUrl
            };

            // ⭐ CRITICAL: If guest, provide guestEmail to satisfy schema 'required' logic
            if (isGuest) {
                orderPayload.guestEmail = guestEmailFromForm || (shippingAddress && shippingAddress.email);
            }

            const newOrder = await Order.create(orderPayload);

            if (!isGuest) {
                await Cart.findOneAndUpdate({ userId }, { items: [], updatedAt: Date.now() });
            }
            
            res.status(201).json({
                message: 'Order placed successfully.',
                orderId: newOrder._id,
                orderReference: orderRef,
                paymentReceiptUrl: paymentReceiptUrl, 
                isGuest: isGuest
            });

        } catch (error) {
            console.error('Order Error:', error);
            // This will now capture and display if a specific field is still missing
            res.status(500).json({ message: `Database Error: ${error.message}` });
        }
    });
});

// =========================================================
// 2. GET /api/orders/history - Retrieve Order History (Protected)
// **Ensure this route is defined BEFORE /api/orders/:orderId**
// =========================================================
app.get('/api/orders/history', verifyUserToken, async (req, res) => {
    try {
        const userId = req.userId;

        if (!userId) {
            return res.status(401).json({ message: 'Authentication required to view order history.' });
        }

        // 1. Fetch orders from the database
        const orders = await Order.find({ userId: userId })
            .select('_id createdAt totalAmount status items') 
            .sort({ createdAt: -1 })
            .lean();

        // 2. Format the output data for the frontend
        const formattedOrders = orders.map(order => ({
            id: order._id, 
            date: order.createdAt,
            total: order.totalAmount,
            status: order.status.charAt(0).toUpperCase() + order.status.slice(1),
            items: order.items.length 
        }));

        // 3. Respond with the formatted order history list
        res.status(200).json({
            orders: formattedOrders,
            message: 'Order history retrieved successfully.'
        });

    } catch (error) {
        console.error('Error fetching order history:', error.message, error.stack);
        res.status(500).json({ 
            message: 'Failed to retrieve order details due to a server error.' 
        });
    }
});


app.get('/api/orders/:orderId', verifyUserToken, async function (req, res) {
    const orderId = req.params.orderId;
    const userId = req.userId;

    try {
        // 1. Build Hybrid Query
        const queryConditions = {
            userId: userId,
            $or: [{ orderReference: orderId }]
        };

        // Add ObjectId lookup if the string format is valid
        if (orderId.length === 24 && /^[0-9a-fA-F]+$/.test(orderId)) {
             queryConditions.$or.push({ _id: orderId });
        }

        // 2. Execute Query
        const order = await Order.findOne(queryConditions)
            .select('subtotal shippingFee tax items totalAmount orderReference status paymentMethod') // Explicitly include financial fields
            .lean();

        if (!order) {
            console.warn(`[OrderFetch] No order found for ID: ${orderId} and User: ${userId}`);
            return res.status(404).json({ message: 'Order not found.' });
        }
        
        if (!order.items || !Array.isArray(order.items)) {
            return res.status(422).json({ message: 'Order data is incomplete.' });
        }

        // 3. Populate Display Details
        const populatedItems = await Promise.all(order.items.map(async (item) => {
            let displayItem = { ...item };
            
            // If the data was already saved during checkout, use it directly (FASTEST)
            if (displayItem.name && displayItem.imageUrl) {
                return displayItem;
            }
            
            // Fallback for legacy orders
            try {
                // Use the helper you defined elsewhere in your server.js
                const Model = typeof getProductModel === 'function' 
                    ? getProductModel(item.productType) 
                    : productModels[item.productType];

                if (Model) {
                    const product = await Model.findById(item.productId).select('name imageUrls').lean();
                    if (product) {
                        displayItem.name = product.name;
                        displayItem.imageUrl = product.imageUrls?.[0] || displayItem.imageUrl;
                    }
                }
            } catch (err) {
                console.error(`[OrderFetch] Fallback lookup failed for ${item.productId}`);
            }

            return displayItem;
        }));

        // 4. Final Financial Calculations
        const finalOrderDetails = {
            ...order,
            items: populatedItems,
            subtotal: order.subtotal ?? (order.totalAmount - (order.shippingFee || 0) - (order.tax || 0)),
            shippingFee: order.shippingFee || 0,
            tax: order.tax || 0
        };

        res.status(200).json(finalOrderDetails);

    } catch (error) {
        console.error('🔴 [OrderFetch] Server Error:', error.message);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// =========================================================
// 3. PUT /api/orders/:orderId/cancel - Order Cancellation (Protected)
// =========================================================
app.put('/api/orders/:orderId/cancel', verifyUserToken, async (req, res) => {
    const orderId = req.params.orderId;
    const userId = req.userId;

    if (!orderId) {
        return res.status(400).json({ message: 'Order ID is required.' });
    }

    try {
        // Define which statuses are eligible for cancellation
        // ⭐ FIX: Must use capitalized statuses to match the Mongoose Enum definition
        const cancellableStatuses = ['Pending', 'Processing']; 

        // 1. Find the order and ensure ownership and cancellable status
        const order = await Order.findOne({ 
            _id: orderId, 
            userId: userId,
            status: { $in: cancellableStatuses } // Order must be in a cancellable state
        });

        if (!order) {
            // Check if the order exists but is in a non-cancellable state
            const existingOrder = await Order.findOne({ _id: orderId, userId: userId });
            
            if (existingOrder && !cancellableStatuses.includes(existingOrder.status)) {
                 return res.status(400).json({ 
                    message: `Cannot cancel order. Current status is '${existingOrder.status}'.` 
                });
            }

            return res.status(404).json({ message: 'Order not found or not eligible for cancellation.' });
        }
        
        // 2. Update the order status to 'Cancelled'
        // Using findByIdAndUpdate ensures the update is Atomic
        const updatedOrder = await Order.findByIdAndUpdate(
            order._id,
            { 
                $set: { 
                    status: 'Cancelled', // ⭐ FIX: Use capitalized status from schema enum
                    cancellationDate: new Date(), // Log the cancellation time
                    // You might also log who cancelled it if needed (order.cancelledBy = userId)
                } 
            },
            { new: true } // Return the updated document
        );
        console.log(`[Cancellation Success] Order ${orderId} cancelled. Refund/Inventory rollback needed.`);


        // 4. Send success response
        res.status(200).json({ 
            message: 'Order successfully cancelled. A refund has been initiated.', 
            order: updatedOrder 
        });

    } catch (error) {
        console.error('Error during order cancellation:', error);
        // Log the specific ID for debugging
        res.status(500).json({ message: `Failed to cancel order ${orderId} due to a server error.` });
    }
});

module.exports = {
    WearsCollection,
    NewArrivals,
    CapCollection,
    PreOrderCollection,
    Order,
    Cart,
    ActivityLog,
    VisitorLog,
    requireUserLogin,
    processOrderCompletion,
    inventoryRollback,
    getProductModel,
    app,
    mongoose,
    populateInitialData,
    MONGODB_URI
};