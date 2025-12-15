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
    'https://outflickzz.netlify.app',
    'https://outflickzz.com' // Make sure you allow your primary domain too
];

const corsOptions = {
    // **1. Keep your existing logic for origin checking (Security)**
    origin: (origin, callback) => {
        // Allow requests with no origin or requests from the allowed list
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    
    credentials: true, 
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
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
 * Utility function to format a number as Naira (NGN) currency.
 * @param {number} amount The amount in NGN (base currency).
 * @returns {string} The formatted currency string.
 */
function formatCurrency(amount) {
    if (typeof amount !== 'number' || isNaN(amount)) {
        return '₦0.00';
    }
    // Using Intl.NumberFormat for robust currency display
    return new Intl.NumberFormat('en-NG', {
        style: 'currency',
        currency: 'NGN'
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
 * This is the final version tailored for admin confirmation.
 * @param {string} customerEmail - The verified email of the customer.
 * @param {Object} order - The final Mongoose order document (status: 'Completed').
 */
async function sendOrderConfirmationEmailForAdmin(customerEmail, order) {
    
    // ✅ FIX: Use the actual final status for the subject.
    // If order.status is falsy (shouldn't happen here), default to 'Completed'.
    const finalStatus = order.status || 'Completed';

    const subject = `✅ Your Order #${order._id.toString().substring(0, 8)} is Confirmed and ${finalStatus}!`; 
    
    // NOTE: The generateOrderEmailHtml function uses fixed variables (SHIPPING_COST, TAX_RATE) 
    // which should be defined in its scope, but it's otherwise acceptable.
    const htmlContent = generateOrderEmailHtml(order); 

    try {
        const info = await sendMail(customerEmail, subject, htmlContent);
        console.log(`Email sent: ${info.messageId} to ${customerEmail}`);
    } catch (error) {
        // Log the email failure but DO NOT re-throw, as the core transaction is complete.
        console.error(`ERROR sending confirmation email for order ${order._id}:`, error);
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
    // Item ID / Product Ref
    productId: { type: mongoose.Schema.Types.ObjectId, required: true },
    name: { type: String, required: true },
    productType: { 
        type: String, 
        required: true, 
      //  enum: ['WearsCollection', 'CapCollection', 'NewArrivals', 'PreOrderCollection'] 
    },
    
    // Variant Details
    size: { type: String, required: true },
    color: { type: String }, 
    variationIndex: { type: Number, required: true, min: 1 },
    
    // 🌟 FIX: Added 'variation' field to store user-friendly name for Order mapping 🌟
    variation: { type: String },
    
    // Pricing & Quantity
    price: { type: Number, required: true, min: 0.01 },
    quantity: { type: Number, required: true, min: 1, default: 1 },
    
    // Media
    imageUrl: { type: String } 
}, { _id: true });

const cartSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true, 
        unique: true 
    },
    items: {
        type: [cartItemSchema],
        default: []
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

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
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
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
            'Pending',              // Bank Transfer awaiting admin/Paystack verification
            'Processing',           // ✅ CRITICAL ADDITION: Intermediate status set by PUT /confirm
            'Shipped',              // Fulfillment statuses
            'Delivered',
            'Cancelled',
            'Confirmed',
            'Refunded',
            'Verification Failed', 
            'Amount Mismatch (Manual Review)',
            'Inventory Failure (Manual Review)', // Better name for inventory rollback
        ], 
        default: 'Pending'
    },
    
    // --- Fulfillment & Payment Details ---
    shippingAddress: { type: Object, required: true },
    paymentMethod: { type: String, required: true },
    orderReference: { type: String, unique: true, sparse: true },
    amountPaidKobo: { type: Number, min: 0 },
    paymentTxnId: { type: String, sparse: true },
    paidAt: { type: Date },
    paymentReceiptUrl: { type: String, sparse: true }, // Bank transfer receipt

    shippedAt: { type: Date, sparse: true }, 
    deliveredAt: { type: Date, sparse: true },
    
    // --- Admin Confirmation Details ---
    confirmedAt: { type: Date, sparse: true },
    confirmedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', sparse: true },
    notes: [String] // For logging manual review notes, inventory failures, etc.
}, { timestamps: true });

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
 * ====================================================================================
 * HELPER FUNCTION: INVENTORY ROLLBACK (Order Status Update)
 * ====================================================================================
 * Updates the order status to indicate a stock failure after a transaction aborts.
 * This is called outside the transaction to persist the failure state immediately.
 * @param {string} orderId The ID of the order that failed.
 * @param {string} reason The error message explaining the failure.
 */
async function inventoryRollback(orderId, reason) {
    try {
        const OrderModel = mongoose.models.Order || mongoose.model('Order');

        await OrderModel.findByIdAndUpdate(
            orderId,
            {
                status: 'Inventory Failure (Manual Review)', 
                notes: [reason], // Add the reason to the notes array for better logging
                updatedAt: Date.now()
            },
            { new: true }
        );
        console.warn(`Order ${orderId} status set to 'Inventory Failure (Manual Review)' and reason logged. Reason: ${reason}`);
    } catch (err) {
        console.error(`CRITICAL: Failed to update order ${orderId} status during rollback.`, err);
        // Do not re-throw, as the main error is already being handled.
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
    // 1. Start a Mongoose session for atomicity (crucial for inventory)
    const session = await mongoose.startSession();
    session.startTransaction();
    let order = null;
    let OrderModel;

    try {
        // Fetch the order within the transaction
        OrderModel = mongoose.models.Order || mongoose.model('Order');
        order = await OrderModel.findById(orderId).session(session);

        // 1.1 Initial check
        const isReadyForInventory = order && 
            (order.status === 'Pending' || order.status === 'Processing');

        if (!isReadyForInventory) {
            await session.abortTransaction();
            
            // 409 Conflict logic: If the order is already in a confirmed state, throw the race error.
            if (order?.status === 'Confirmed' || order?.status === 'Completed') {
                console.warn(`Order ${orderId} is already confirmed (${order.status}). Inventory deduction skipped.`);
                const raceError = new Error("Order already processed or is being processed.");
                raceError.isRaceCondition = true;
                throw raceError; 
            }
            
            console.warn(`Order ${orderId} skipped: not found or status is ${order?.status}. Inventory deduction aborted.`);
            return order; // Return the current state of the order
        }

        // 2. Loop through each item to deduct stock...
        for (const item of order.items) {
            const ProductModel = getProductModel(item.productType); 
            const quantityOrdered = item.quantity;
            let updatedProduct;
            let errorMsg;

            // =============================================================================
            // ⭐ CORE FIX: CONDITIONAL INVENTORY DEDUCTION LOGIC ⭐
            // =============================================================================
            
            // --- Group 1: Items with nested 'sizes' array (Wears, NewArrivals, PreOrder) ---
            if (item.productType === 'WearsCollection' || 
                item.productType === 'NewArrivals' || 
                item.productType === 'PreOrderCollection') {
                
                if (!item.size) { // Add a check for size-required products
                    errorMsg = `Missing size information for size-based product ${item.productId} in ${item.productType}.`;
                    throw new Error(errorMsg);
                }

                updatedProduct = await ProductModel.findOneAndUpdate(
                    {
                        _id: item.productId,
                        // 🔑 FIX: Only match the product ID and the variation index in the top-level filter.
                        // The critical size and stock check is now solely handled by the arrayFilters.
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
                            // Filter 1: Match the correct outer Variation ('var')
                            { 'var.variationIndex': item.variationIndex }, 
                            // Filter 2: Match the correct inner Size ('size') AND the atomic stock check
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
                            // 🔑 FIX: Use $elemMatch in the main query to perform the atomic stock check
                            $elemMatch: {
                                variationIndex: item.variationIndex, // Find the correct variation
                                stock: { $gte: quantityOrdered }      // Check stock directly on variation
                            }
                        }
                    },
                    {
                        $inc: {
                            // Decrement stock directly on the variation found by the filter
                            'variations.$[var].stock': -quantityOrdered, 
                            'totalStock': -quantityOrdered 
                        }
                    },
                    {
                        new: true,
                        session: session, 
                        arrayFilters: [
                            // Filter by variation index to ensure only the matched element is updated
                            { 'var.variationIndex': item.variationIndex } 
                        ]
                    }
                );
            
            // --- Fallback for unsupported types ---
            } else {
                errorMsg = `Unsupported product type found: ${item.productType}. Inventory deduction aborted.`;
                throw new Error(errorMsg);
            }
            // =============================================================================
            
            // Check if the update was successful (product found and stock condition met)
            if (!updatedProduct) {
                // Determine the size label for the error message
                const sizeLabel = item.productType === 'CapCollection' ? 'N/A (Direct Stock)' : item.size;
                
                const finalErrorMsg = `Insufficient stock or product data mismatch for item: ${sizeLabel} of product ${item.productId} in ${item.productType}. Transaction aborted.`;
                throw new Error(finalErrorMsg);
            }
            
            console.log(`Inventory deducted for Product ID: ${item.productId}, Type: ${item.productType}, Qty: ${quantityOrdered}`);
        }

        // 5. Update order status and confirmation details atomically
        order.status = 'Confirmed';
        order.confirmedAt = new Date(); 
        order.confirmedBy = adminId; 
        await order.save({ session });

        // 6. Finalize transaction
        await session.commitTransaction();
        console.log(`Order ${orderId} successfully confirmed and inventory fully deducted. Status: Confirmed.`);
        return order.toObject({ getters: true });

    } catch (error) {
        // Rollback on any failure
        if (session.inTransaction()) {
            await session.abortTransaction();
        }
        
        if (error.isRaceCondition) {
            console.warn(`Race condition handled for order ${orderId}. No rollback status update needed.`);
        }
        else if (order) { 
            // Call inventoryRollback for genuine failures (like Insufficient Stock)
            await inventoryRollback(orderId, error.message);
        }

        throw error;
    } finally {
        session.endSession();
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
            .populate('userId', 'email username') // Populate User info needed for display
            .lean(); // Use .lean() for faster read performance

        // NOTE: The 'collection' filter on the frontend is challenging 
        // because it's stored in the nested 'items' array.
        // For simple display, the current fetch is enough.

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
 * Generates a short-lived Access Token (e.g., 15 minutes) for user API access.
 */
function generateUserAccessToken(payload) {
    return jwt.sign({ ...payload, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '15m' }); 
}

/**
 * Generates a long-lived Refresh Token (e.g., 7 days) for user session persistence.
 */
function generateUserRefreshToken(payload) {
    return jwt.sign({ ...payload, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '7d' }); 
}

// Define isProduction at the top level
const isNetlifyProduction = process.env.NODE_ENV === 'production' || process.env.NETLIFY === 'true';

const getCookieOptions = (req) => {
    // If running on Netlify (or production) AND request is HTTPS
    const isSecure = isNetlifyProduction && req.headers['x-forwarded-proto'] === 'https';
    
    // Fallback: If on Netlify, assume secure for cookie attributes
    const secureCookieAttribute = isSecure || process.env.NODE_ENV === 'production'; // This is the crucial change
    
    return {
        httpOnly: true,
        // FORCE 'Secure' if we are likely in a production/HTTPS environment
        secure: secureCookieAttribute, 
        sameSite: 'None', 
    };
};
// --- EXPRESS CONFIGURATION AND MIDDLEWARE ---
const app = express();
// Ensure express.json() is used BEFORE the update route, but after the full form route
// To allow both JSON and multipart/form-data parsing

app.use(cors(corsOptions));
app.use(express.json()); 
app.use(cookieParser());

app.use(visitorLogger);

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

const verifyUserToken = (req, res, next) => {
    // 1. Check for token in the 'Authorization: Bearer <token>' header
    // The short-lived Access Token should be strictly sent here by the client for speed.
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // If the Access Token is missing from the header, deny access.
        return res.status(401).json({ message: 'Access denied. No Access Token provided in header.' });
    }

    // 2. Extract the Access Token
    const accessToken = authHeader.split(' ')[1];

    try {
        // 3. Verify the Access Token (Fast, stateless check)
        // Assuming JWT_SECRET is available in scope
        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
        
        // 4. Ensure this is a regular user token 
        if (decoded.role !== 'user') {
            return res.status(403).json({ message: 'Forbidden. Invalid token role for user access.' });
        }
        
        // 5. Success: Attach the user ID and proceed
        req.userId = decoded.id; 
        next();
        
    } catch (err) {
        // 6. Handle verification errors
        
        // --- 🔑 HIGH-PERFORMANCE REFRESH HANDLING ---
        if (err.name === 'TokenExpiredError') {
            // Access Token is expired, but valid. Signal the client to 
            // silently call the /api/users/refresh endpoint using the secure Refresh Token cookie.
            return res.status(401).json({ 
                message: 'Access Token expired. Refresh required.',
                expired: true // CRITICAL flag for the client to initiate refresh flow
            });
        }
        
        // For all other errors (invalid signature, tampering, etc.), force re-login
        // No need to clear the cookie here; the Refresh Endpoint handles clearing its own cookie on failure.
        console.error("JWT Verification Error:", err.message);
        res.status(401).json({ message: 'Invalid token signature. Please log in again.' });
    }
};

const verifySessionCookie = (req, res, next) => {
    // ------------------- 💡 DEBUG LOGGING ADDED -------------------
    // Log incoming cookie headers to see if the browser sent anything at all.
    // The 'cookie' header is what the browser sends.
    console.log('DEBUG COOKIE CHECK: Incoming Cookie Header:', req.headers.cookie);
    // -----------------------------------------------------------------

    // 1. Get Refresh Token from the secure cookie
    const refreshToken = req.cookies.userRefreshToken; 
    
    // ------------------- 💡 DEBUG LOGGING ADDED -------------------
    console.log('DEBUG REFRESH TOKEN:', refreshToken ? 'Token FOUND' : 'Token MISSING from req.cookies');
    // -----------------------------------------------------------------

    if (!refreshToken) {
        // If NO cookie is found, the user is NOT logged in.
        return res.status(401).json({ message: 'No valid session cookie found.' });
    }

    try {
        // 2. Verify the Refresh Token
        // NOTE: Ensure process.env.JWT_SECRET is identical to the one used for signing.
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        
        // 3. Ensure role is correct (optional but good practice)
        if (decoded.role !== 'user') {
            return res.status(403).json({ message: 'Forbidden. Invalid token role in cookie.' });
        }

        // 4. Success: User is authenticated via session cookie.
        req.userId = decoded.id; 
        
        console.log('DEBUG REFRESH TOKEN: Verification SUCCESS. Proceeding...');
        next(); 

    } catch (err) {
        // 5. If refresh token is expired/invalid/bad signature
        console.error("Session Cookie verification failed:", err.message);
        
        // In a real environment, you should clear the cookie here using the
        // consistent 'SameSite=None; Secure' settings before sending 401.
        
        res.status(401).json({ message: 'Session cookie invalid or expired.' });
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
        console.log("Attempting to retrieve all order data for Sales Log...");
        
        // Call the new function
        const orders = await getAllOrders();
        
        console.log(`Successfully retrieved ${orders.length} orders.`);
        
        // Return the orders array
        res.status(200).json(orders);
        
    } catch (error) {
        console.error("Sales Log API Crash Detected:", error);
        res.status(500).json({ 
            message: 'Failed to retrieve all order records.',
            internalError: error.message
        });
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
        // Fetch all users. Select only necessary fields and exclude the password (which is selected: false by default, but we re-specify for clarity).
        const users = await User.find({})
            .select('email profile address status membership')
            .lean(); // Use .lean() for faster query performance since we are only reading

        // Transform the data to match the frontend's expected format (if needed, but here we just return the array)
        const transformedUsers = users.map(user => ({
            _id: user._id,
            name: `${user.profile.firstName || ''} ${user.profile.lastName || ''}`.trim() || 'N/A',
            email: user.email,
            isMember: user.status.role === 'vip', // Determine membership status
            createdAt: user.membership.memberSince,
            // Include other fields if the admin needs them, but for the table, this is enough
        }));


        // Success Response
        return res.status(200).json({ 
            users: transformedUsers,
            count: transformedUsers.length
        });

    } catch (error) {
        console.error('Admin user fetch error:', error);
        // Return a generic server error
        return res.status(500).json({ message: 'Server error: Failed to retrieve user list.' });
    }
});

// EXISTING: 1. GET /api/admin/users/:id (Fetch Single User Profile - Protected Admin)
app.get('/api/admin/users/:id', verifyToken, async (req, res) => {
    try {
        const userId = req.params.id;

        const user = await User.findById(userId)
            .select('email profile address status membership')
            .lean();

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const addressParts = [
            user.address?.street,
            user.address?.city,
            user.address?.state,
            user.address?.zip,
            user.address?.country
        ].filter(Boolean);
        
        const contactAddress = addressParts.length > 0 ? addressParts.join(', ') : 'No Address Provided';

        const detailedUser = {
            _id: user._id,
            name: `${user.profile.firstName || ''} ${user.profile.lastName || ''}`.trim() || 'N/A',
            email: user.email,
            isMember: user.status.role === 'vip',
            createdAt: user.membership.memberSince,
            phone: user.profile.phone || 'N/A',
            // --- 📢 NEW ADDITION FOR WHATSAPP CONTACT 📢 ---
            whatsappNumber: user.profile.whatsapp || 'N/A', 
            // ----------------------------------------------------
            contactAddress: contactAddress
        };

        return res.status(200).json({ 
            user: detailedUser
        });

    } catch (error) {
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ message: 'Invalid User ID format.' });
        }
        console.error('Admin single user fetch error:', error);
        return res.status(500).json({ message: 'Server error: Failed to retrieve user details.' });
    }
});

// NEW: 2. GET /api/admin/users/:userId/orders (Fetch User Order History - Protected Admin)
app.get('/api/admin/users/:userId/orders', verifyToken, async (req, res) => {
    try {
        const userId = req.params.userId;

        // 1. Validate the user exists (Optional, but good practice)
        const userExists = await User.exists({ _id: userId });
        if (!userExists) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // 2. Fetch all orders for that user ID
        // Sort by creation date descending (newest first)
        const userOrders = await Order.find({ userId: userId }) 
            .sort({ createdAt: -1 })
            .lean(); // Returns plain JavaScript objects

        // 3. Simple transformation: Since OrderItemSchema is now denormalized 
        //    (includes name and imageUrl), we can return the data directly.
        const augmentedOrders = userOrders.map(order => ({
            ...order,
            // Items already contain name and imageUrl from the denormalized schema
            items: order.items || [], 
        }));

        // Success Response
        return res.status(200).json({ 
            orders: augmentedOrders,
            count: augmentedOrders.length
        });

    } catch (error) {
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ message: 'Invalid User ID format.' });
        }
        console.error('Admin user orders fetch error:', error);
        return res.status(500).json({ message: 'Server error: Failed to retrieve user order history.' });
    }
});


// =========================================================
// 8. GET /api/admin/orders/pending - Fetch All Pending Orders (Admin Protected)
// =========================================================
app.get('/api/admin/orders/pending', verifyToken, async (req, res) => {
    try {
        // Find all orders where the status is 'Pending'
        const pendingOrders = await Order.find({ status: 'Pending' })
            .select('_id userId totalAmount createdAt status paymentMethod paymentReceiptUrl subtotal shippingFee tax')
            .sort({ createdAt: 1 })
            .lean();

        // 1. Get User Details for each pending order (for 'Customer' column)
        const populatedOrders = await Promise.all(
            pendingOrders.map(async (order) => {
                const user = await User.findById(order.userId)
                    // ✅ FIX 1: Select nested fields from the 'profile' subdocument
                    .select('profile.firstName profile.lastName email') 
                    .lean();

                // ✅ FIX 2: Access nested fields safely
                const firstName = user?.profile?.firstName;
                const lastName = user?.profile?.lastName;
                
                // Construct userName: Use full name if both exist, otherwise fall back to email
                const userName = (firstName && lastName) 
                    ? `${firstName} ${lastName}` 
                    : user?.email || 'N/A'; // Final fallback to email or 'N/A'
                
                const email = user ? user.email : 'Unknown User';
                
                return {
                    ...order,
                    userName: userName, // Added for the Admin table
                    email: email,       // Added for the Admin table
                };
            })
        );

        // Send the complete list of pending orders
        res.status(200).json(populatedOrders);

    } catch (error) {
        console.error('Error fetching pending orders:', error);
        res.status(500).json({ message: 'Failed to retrieve pending orders.' });
    }
});

// =========================================================
// 8b. GET /api/admin/orders/:orderId - Fetch Single Detailed Order (Admin Protected)
// =========================================================
app.get('/api/admin/orders/:orderId', verifyToken, async (req, res) => {
    try {
        const orderId = req.params.orderId;

        // 1. Fetch the single order
        let order = null;
        
        // CRITICAL FIX: Try finding by MongoDB _id first (standard practice)
        // If orderId is a valid ObjectId, findById will work.
        if (orderId.match(/^[0-9a-fA-F]{24}$/)) {
             order = await Order.findById(orderId).lean();
        }

        // If not found by _id (or if it wasn't a valid ObjectId format), 
        // try searching by the orderReference field, which is often used in logs.
        if (!order) {
            console.log(`[Order Fetch] Attempting to find order by orderReference: ${orderId}`);
            order = await Order.findOne({ orderReference: orderId }).lean();
        }

        if (!order) {
            return res.status(404).json({ message: 'Order not found.' });
        }
        
        // 2. Augment order items with product details (name, imageUrl)
        const detailedOrders = await augmentOrdersWithProductDetails([order]);
        let detailedOrder = detailedOrders[0];

        // 🚨 FIX: Generate Signed URL for the Payment Receipt
        if (detailedOrder.paymentReceiptUrl) {
            // Assuming generateSignedUrl is an async helper function
            detailedOrder.paymentReceiptUrl = await generateSignedUrl(detailedOrder.paymentReceiptUrl);
        }

        // 3. Get User Details (Name and Email)
        const user = await User.findById(detailedOrder.userId)
            .select('profile.firstName profile.lastName email') 
            .lean();

        const firstName = user?.profile?.firstName;
        const lastName = user?.profile?.lastName;

        // Construct userName: Use full name if both exist, otherwise fall back to email
        const userName = (firstName && lastName) 
            ? `${firstName} ${lastName}` 
            : user?.email || 'N/A';
            
        const email = user ? user.email : 'Unknown User';
        
        // 4. Combine all details
        const finalDetailedOrder = {
            ...detailedOrder,
            // Ensure customerName is explicitly set, as the frontend uses order.customerName
            customerName: userName, 
            email: email,
            // Explicitly include the total quantity for the frontend to calculate Total Items Deducted
            totalQuantity: detailedOrder.items.reduce((sum, item) => sum + (item.quantity || 0), 0)
        };

        // 🚀 FIX APPLIED HERE: Wrap the finalDetailedOrder object in a parent object with the 'order' key.
        return res.status(200).json({ 
            order: finalDetailedOrder 
        });

    } catch (error) {
        console.error(`Error fetching order details for ${req.params.orderId}:`, error);
        if (error.name === 'CastError' || error.kind === 'ObjectId') {
             return res.status(400).json({ message: 'Invalid Order ID format.' });
        }
        return res.status(500).json({ message: 'Server error: Failed to retrieve order details.' });
    }
});

// =========================================================
// (All other endpoints remain the same)
// =========================================================
// =========================================================
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
            { _id: orderId, status: 'Pending' }, 
            { 
                $set: { 
                    status: 'Processing', // Claim the order for this worker thread
                    confirmedAt: new Date(), 
                    confirmedBy: adminId 
                } 
            },
            { new: true, select: 'userId status totalAmount items' } 
        ).lean();

        // Check if the order was successfully found and updated.
        if (!updatedOrder) {
            console.warn(`Order ${orderId} skipped: not found or status is not pending.`);
            const checkOrder = await Order.findById(orderId).select('status').lean();
            if (checkOrder) {
                console.warn(`[Inventory Skip Reason] Order ${orderId} is currently in status: ${checkOrder.status}.`);
            } else {
                console.warn(`[Inventory Skip Reason] Order ${orderId} does not exist.`);
            }
            
            // Use 409 Conflict to indicate that the request could not be completed due to the resource's state.
            return res.status(409).json({ message: 'Order not found or is already processed.' });
        }
        
        // 2. CRITICAL STEP: Deduct Inventory and finalize status to 'Confirmed' atomically
        let finalOrder;
        try {
            console.log(`[Inventory] Attempting atomic inventory deduction for Order ${orderId}.`);
            // The helper now handles the final transition to 'Confirmed'
            finalOrder = await processOrderCompletion(orderId, adminId); 
            // 🎯 UPDATED LOG: Reflects the final 'Confirmed' status set by the helper
            console.log(`[Inventory Success] Inventory deduction completed successfully for Order ${orderId}. Final status: ${finalOrder.status}.`);
            
        } catch (inventoryError) {
            
            // --- Handle Business Logic Conflict Separately (Race Condition) ---
            if (inventoryError.isRaceCondition) {
                console.warn(`Race condition detected: Order ${orderId} confirmed by concurrent request. Returning 200.`);
                
                // Fetch the now-confirmed order to return a successful response to the admin UI
                const confirmedOrder = await Order.findById(orderId).lean();
                
                // Log and return 200 OK for concurrent confirmation
                console.warn(`[Inventory Race Skip] Inventory deduction was skipped because the order was finalized by a concurrent process. Current status: ${confirmedOrder.status}.`);

                return res.status(200).json({ 
                    // 🎯 UPDATED MESSAGE: Use the confirmedOrder's current status (likely 'Confirmed')
                    message: `Order ${orderId} was confirmed by a concurrent request. Status: ${confirmedOrder.status}.`,
                    order: confirmedOrder 
                });
            }
            
            // Rollback status if inventory fails (Genuine stock insufficient errors)
            console.error('Inventory deduction failed during Admin confirmation:', inventoryError.message);
            
            // The rollback function (called by processOrderCompletion's catch) has already set the status 
            // to 'Inventory Failure (Manual Review)'. We only add an extra note here.
            await Order.findByIdAndUpdate(orderId, { 
                $push: { notes: `Inventory deduction failed on ${new Date().toISOString()}: ${inventoryError.message}` }
            });
            
            // Return 409 Conflict for known business logic failure (Insufficient Stock).
            return res.status(409).json({ 
                message: 'Payment confirmed, but inventory deduction failed. Order status flagged for manual review.',
                error: inventoryError.message
            });
        }
        
        // 3. GET CUSTOMER EMAIL & SEND NOTIFICATION 📧
        const user = await User.findById(updatedOrder.userId).select('email').lean();
        const customerEmail = user ? user.email : null;

        if (customerEmail) {
            try {
                // Email is only sent if the inventory transaction (step 2) succeeded
                console.log(`[Email] Sending confirmation email to: ${customerEmail} for order ${orderId}.`);
                await sendOrderConfirmationEmailForAdmin(customerEmail, finalOrder);
                console.log(`[Email Success] Confirmation email sent to ${customerEmail}.`);
            } catch (emailError) {
                console.error(`[Email Failure Reason] CRITICAL WARNING: Failed to send confirmation email to ${customerEmail} (Order ${orderId}):`, emailError.message);
                // Continue execution to send the success response to the client
            }
        } else {
            console.warn(`[Email Skip Reason] Could not find email for user ID: ${updatedOrder.userId}. Skipping email notification.`);
        }
        
        // ⭐ INTEGRATION: Log the successful confirmation action
        if (finalOrder) {
            // We assume finalOrder has the required fields (userId, _id, totalAmount)
            await logAdminOrderAction(finalOrder, adminId, 'ORDER_CONFIRMED'); 
        }

        // 4. Success Response
        res.status(200).json({ 
            // 🎯 UPDATED MESSAGE: The final status will now be 'Confirmed'
            message: `Order ${orderId} confirmed, inventory deducted, and customer notified. Status: ${finalOrder.status}.`,
            order: finalOrder 
        });

    } catch (error) {
        // This catch block handles the final crash and returns the 500 error
        console.error(`Error confirming order ${orderId}:`, error);
        res.status(500).json({ message: 'Failed to confirm order due to a server error.' });
    }
});

// =========================================================
// 10. PUT /api/admin/orders/:orderId/status - Update Fulfillment Status
// =========================================================
app.put('/api/admin/orders/:orderId/status', verifyToken, async (req, res) => {
    const { orderId } = req.params;
    const { newStatus } = req.body; 
    
    // 🎯 CRITICAL FIX: Fulfillment MUST start from 'Confirmed'.
    // This prevents an admin from shipping an order that failed inventory (status: Processing)
    const validTransitions = {
        'Confirmed': 'Shipped',
        'Shipped': 'Delivered'
    };
    
    let updateFields = { status: newStatus };
    let finalOrder = null;

    if (!orderId || !newStatus) {
        return res.status(400).json({ message: 'Order ID and a new status are required.' });
    }

    try {
        // Fetch the full order for context and email
        const order = await Order.findById(orderId).lean();

        if (!order) {
            return res.status(404).json({ message: 'Order not found.' });
        }

        const currentStatus = order.status;
        const expectedNextStatus = validTransitions[currentStatus];

        // 1. Validate Status Transition - The Guardrail
        if (newStatus !== expectedNextStatus) {
            console.warn(`[Fulfillment Guardrail Fail] Invalid transition from ${currentStatus} to ${newStatus}. Must be 'Confirmed' to ship.`);
            return res.status(400).json({ 
                message: `Invalid status transition from ${currentStatus} to ${newStatus}. Order must be Confirmed to move to Shipped.` 
            });
        }
        
        // ... (Remaining logic for Shipped/Delivered handling is correct) ...

        // 2. Handle 'Shipped' transition (No tracking number/company)
        if (newStatus === 'Shipped') {
            updateFields = { 
                ...updateFields, 
                // Only setting the timestamp
                shippedAt: new Date()
            };
        }
        
        // 3. Handle 'Delivered' transition
        if (newStatus === 'Delivered') {
              updateFields = { 
                ...updateFields, 
                deliveredAt: new Date()
            };
        }

        // 4. Perform the atomic status update
        finalOrder = await Order.findByIdAndUpdate(
            orderId, 
            { $set: updateFields },
            { new: true }
        ).lean();

        // 5. Send Email Notification (Logic remains, but emails should be simpler)
        const user = await User.findById(finalOrder.userId).select('email').lean();
        const customerEmail = user ? user.email : null;

        if (customerEmail) {
            try {
                if (newStatus === 'Shipped') {
                    await sendShippingUpdateEmail(customerEmail, finalOrder); 
                } else if (newStatus === 'Delivered') {
                    await sendDeliveredEmail(customerEmail, finalOrder);
                }
            } catch (emailError) {
                console.error(`WARNING: Failed to send ${newStatus} email to ${customerEmail}:`, emailError.message);
            }
        }
        
        // ⭐ INTEGRATION: Log the shipping/delivery action
        if (finalOrder) {
            const logEventType = newStatus === 'Shipped' ? 'ORDER_SHIPPED' : 'ORDER_DELIVERED';
            // We assume req.adminId is available from verifyToken
            await logAdminStatusUpdate(finalOrder, req.adminId, logEventType); 
        }

        // 6. Success Response
        res.status(200).json({ 
            message: `Order ${orderId} status successfully updated to ${newStatus}.`,
            order: finalOrder 
        });

    } catch (error) {
        console.error(`Error updating order status ${orderId}:`, error);
        res.status(500).json({ message: 'Failed to update order status due to a server error.' });
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

/**
 * GET /api/admin/newarrivals - Fetch All New Arrivals
 * Fetches all products, sorts them, and generates signed URLs for all variation images.
 */
app.get('/api/admin/newarrivals', verifyToken, async (req, res) => {
    try {
        // 1. Fetch all products
        const products = await NewArrivals.find({})
            .select('_id name tag price variations totalStock isActive')
            .sort({ createdAt: -1 })
            .lean();

        // 2. Sign URLs for all products
        const signedProducts = await Promise.all(products.map(async (product) => {
            const signedVariations = await Promise.all(product.variations.map(async (v) => ({
                ...v,
                // Generate signed URLs for image retrieval
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

/**
 * GET /api/admin/newarrivals/:id - Fetch Single New Arrival
 * Fetches a single product by ID and generates signed URLs for its variation images.
 */
app.get('/api/admin/newarrivals/:id', verifyToken, async (req, res) => {
    try {
        const productId = req.params.id;
        const product = await NewArrivals.findById(productId).lean();

        if (!product) {
            return res.status(404).json({ message: 'Product not found.' });
        }

        // Sign URLs
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
                tag: productData.tag,
                price: productData.price, 
                // The sizes field was correctly removed from the main schema, 
                // so we don't try to assign productData.sizes here.
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

// GET /api/admin/wearscollections/:id (Fetch Single Collection)
app.get('/api/admin/wearscollections/:id', verifyToken, async (req, res) => {
    try {
        // --- FIX 1: Ensure totalStock is selected for fetching ---
        const collection = await WearsCollection.findById(req.params.id)
            .select('_id name tag price variations sizesAndStock isActive totalStock') 
            .lean(); 
        
        if (!collection) {
            return res.status(404).json({ message: 'Collection not found.' });
        }

        // Sign URLs
        const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
            ...v,
            frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl, 
            backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl 
        })));
        
        collection.variations = signedVariations;

        res.status(200).json(collection);
    } catch (error) {
        console.error('Error fetching wear collection:', error);
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
            existingCollection.tag = collectionData.tag;
            existingCollection.price = collectionData.price;
            
            // --- FIX 5: Assign totalStock from client payload ---
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
            tag: collectionData.tag,
            price: collectionData.price,
            // REMOVED: sizes - now nested in variations
            // REMOVED: totalStock - calculated automatically by pre('save') middleware
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
            existingCollection.price = collectionData.price;
            // REMOVED: sizes and totalStock from top-level update
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
                .select('_id name tag price variations totalStock isActive availableDate') 
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

// =========================================================
// 11. GET /api/admin/inventory/deductions - Fetch Deducted Inventory Logs (Admin Protected)
// =========================================================
app.get('/api/admin/inventory/deductions', verifyToken, async (req, res) => {
    try {
        // Get the category filter from the query parameter (e.g., ?category=wears)
        const categoryFilter = req.query.category ? req.query.category.toLowerCase() : 'all';
        
        // Map the URL filter string to the Mongoose Model Name
        const categoryMap = {
            'wears': 'WearsCollection', 
            'caps': 'CapCollection', 
            'newarrivals': 'NewArrivals', 
            'preorders': 'PreOrderCollection' 
        };
        
        // 1. Initial Match Stage (Filter by Order Status)
        // We only care about orders where inventory was actually deducted ('Confirmed' or later)
        let pipeline = [
            {
                $match: {
                    status: { $in: ['Confirmed', 'Shipped', 'Delivered'] }
                }
            },
            // 2. Unwind the 'items' array
            // This creates a separate document for every single product line item in every order.
            {
                $unwind: '$items'
            }
        ];
        
        // 3. Optional Match Stage (Filter by Category)
        if (categoryFilter !== 'all') {
            const productType = categoryMap[categoryFilter];
            if (productType) {
                pipeline.push({
                    $match: {
                        'items.productType': productType // Filter on the specific collection/model name
                    }
                });
            } else {
                // Handle invalid category query gracefully
                return res.status(400).json({ message: 'Invalid category filter provided.' });
            }
        }
        
        // 4. Project Stage (Reshape the data for the frontend log)
        pipeline.push({
            $project: {
                _id: 0, // Exclude the default _id from the order document
                
                // Fields needed by the frontend:
                productId: '$items.productId',
                name: '$items.name',
                category: '$items.productType', // Use productType as the category name
                quantity: '$items.quantity', 
                orderId: '$_id', // The original order ID
                date: '$confirmedAt', // The date the deduction happened
                
                // Optional: Include the Admin who confirmed the order
                confirmedBy: '$confirmedBy' 
            }
        });

        // 5. Sort Stage (Newest deductions first)
        pipeline.push({
            $sort: { date: -1 } 
        });

        // Execute the aggregation pipeline on the Order model
        const OrderModel = mongoose.models.Order || mongoose.model('Order');
        const deductionLogs = await OrderModel.aggregate(pipeline);

        // Map the raw productType string to a cleaner display name for the frontend
        const deductionLogsFormatted = deductionLogs.map(log => ({
            ...log,
            category: log.category.replace('Collection', '').replace('PreOrder', 'Pre-Order')
        }));

        res.status(200).json(deductionLogsFormatted);

    } catch (error) {
        console.error('Error fetching inventory deduction log:', error);
        res.status(500).json({ message: 'Failed to retrieve inventory deduction logs.' });
    }
});

// GET /api/collections/wears (For Homepage Display)
app.get('/api/collections/wears', async (req, res) => {
    try {
        const collections = await WearsCollection.find({ isActive: true }) 
            .select('_id name tag price variations totalStock') // Ensure 'variations' is selected!
            .sort({ createdAt: -1 })
            .lean(); 

        const publicCollections = await Promise.all(collections.map(async (collection) => {
            
            const sizeStockMap = {}; // Will store {S: 10, M: 0, L: 5}

            // --- CRITICAL: Variables for OOS Image Fallback ---
            // Stores the image URLs (SIGNED) of the very first variation encountered.
            let fallbackFrontImageUrl = null;
            let fallbackBackImageUrl = null;
            const PLACEHOLDER_S3_PATH = 'public/placeholder-image-v1.jpg'; // Adjust if path is different

            // --- CRITICAL: Filter Variants and Aggregate Stock ---
            const filteredVariantsWithStock = [];

            for (const v of collection.variations || []) { // Added || [] for safe iteration
                
                // 1. SIGN THE VARIATION IMAGES (always needed for the frontend variants array or fallback)
                const signedFrontUrl = await generateSignedUrl(v.frontImageUrl);
                const signedBackUrl = await generateSignedUrl(v.backImageUrl);

                // 2. Capture the first signed URL encountered for the OOS fallback
                if (!fallbackFrontImageUrl && signedFrontUrl) {
                    fallbackFrontImageUrl = signedFrontUrl;
                    fallbackBackImageUrl = signedBackUrl;
                }
                
                // 3. Calculate total stock for THIS specific color (variant)
                const variantTotalStock = (v.sizes || []).reduce((sum, s) => sum + (s.stock || 0), 0);
                
                // 4. ONLY INCLUDE THE VARIANT IF IT HAS STOCK
                if (variantTotalStock > 0) {
                    
                    // 5. Aggregate size stock for the top-level sizeStockMap
                    (v.sizes || []).forEach(s => {
                        const normalizedSize = s.size.toUpperCase().trim();
                        // Only aggregate if the size itself has stock
                        if (s.stock > 0) {
                            sizeStockMap[normalizedSize] = (sizeStockMap[normalizedSize] || 0) + s.stock;
                        }
                    });

                    // 6. Map and prepare the public variant object (FOR IN-STOCK SELECTION)
                    filteredVariantsWithStock.push({
                        color: v.colorHex,
                        frontImageUrl: signedFrontUrl || 'https://placehold.co/400x400/111111/FFFFFF?text=Front+View+Error',
                        backImageUrl: signedBackUrl || 'https://placehold.co/400x400/111111/FFFFFF?text=Back+View+Error',
                        // NOTE: Do NOT include sizes/stock here, as the client filters sizes based on sizeStockMap
                    });
                }
            }
            // --- END CRITICAL FILTERING ---

            // --- CRITICAL IMAGE FIX: ENSURE A SIGNED FALLBACK URL IS ALWAYS PRESENT ---
            if (!fallbackFrontImageUrl) {
                // If the variations array was empty or contained no valid URLs, 
                // sign the generic placeholder path.
                const signedPlaceholder = await generateSignedUrl(PLACEHOLDER_S3_PATH);
                fallbackFrontImageUrl = signedPlaceholder;
                fallbackBackImageUrl = signedPlaceholder;
            }
            // --- END CRITICAL IMAGE FIX ---
            
            return {
                _id: collection._id,
                name: collection.name,
                tag: collection.tag,
                price: collection.price, 
                frontImageUrl: fallbackFrontImageUrl,  // <<-- OOS/Fallback Image
                backImageUrl: fallbackBackImageUrl,    // <<-- OOS/Fallback Image
                sizeStockMap: sizeStockMap,
                availableStock: collection.totalStock, 
                variants: filteredVariantsWithStock      // <<-- In-Stock variants
            };
        }));

        res.status(200).json(publicCollections);
    } catch (error) {
        console.error('Error fetching public wear collections:', error);
        res.status(500).json({ message: 'Server error while fetching collections for homepage.', details: error.message });
    }
});

// GET /api/collections/newarrivals (For Homepage Display)
app.get('/api/collections/newarrivals', async (req, res) => {
    try {
        const products = await NewArrivals.find({ isActive: true }) 
            .select('_id name tag price variations totalStock') 
            .sort({ createdAt: -1 })
            .lean(); 

        const publicProducts = await Promise.all(products.map(async (product) => {
            
            const sizeStockMap = {}; 
            
            // --- CRITICAL: Variables for OOS Image Fallback ---
            let fallbackFrontImageUrl = null;
            let fallbackBackImageUrl = null;
            const PLACEHOLDER_S3_PATH = 'public/placeholder-image-v1.jpg'; // Path to your default placeholder

            // --- CRITICAL: Filter Variants and Aggregate Stock ---
            const filteredVariantsWithStock = [];

            for (const v of product.variations || []) {
                
                // 1. SIGN THE VARIATION IMAGES
                const signedFrontUrl = await generateSignedUrl(v.frontImageUrl);
                const signedBackUrl = await generateSignedUrl(v.backImageUrl);
                
                // 2. Capture the first signed URL encountered for the OOS fallback (Runs once)
                if (!fallbackFrontImageUrl && signedFrontUrl) {
                    fallbackFrontImageUrl = signedFrontUrl;
                    fallbackBackImageUrl = signedBackUrl;
                }
                
                // 3. Calculate total stock for THIS specific color (variant)
                const variantTotalStock = (v.sizes || []).reduce((sum, s) => sum + (s.stock || 0), 0);
                
                // 4. ONLY INCLUDE THE VARIANT IF IT HAS STOCK
                if (variantTotalStock > 0) {
                    
                    // 5. Aggregate size stock for the top-level sizeStockMap
                    (v.sizes || []).forEach(s => {
                        const normalizedSize = s.size.toUpperCase().trim();
                        if (s.stock > 0) {
                            sizeStockMap[normalizedSize] = (sizeStockMap[normalizedSize] || 0) + s.stock;
                        }
                    });

                    // 6. Map and prepare the public variant object
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
            // --- END CRITICAL FILTERING ---

            // --- CRITICAL IMAGE FIX: Failsafe for Missing Data ---
            if (!fallbackFrontImageUrl) {
                const signedPlaceholder = await generateSignedUrl(PLACEHOLDER_S3_PATH);
                fallbackFrontImageUrl = signedPlaceholder;
                fallbackBackImageUrl = signedPlaceholder;
            }
            // --- END CRITICAL IMAGE FIX ---

            return {
                _id: product._id,
                name: product.name,
                tag: product.tag,
                price: product.price, 
                // 💡 OOS/Fallback Images
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
            .select('_id name tag price totalStock availableDate variations')
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
            .select('_id name tag price variations totalStock') 
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
        // FIX: Explicitly select the hidden fields for the verification check
        const user = await User.findOne({ email })
            .select('+verificationCode +verificationCodeExpires');

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // 1. Check if already verified
        if (user.status && user.status.isVerified) { 
             return res.status(400).json({ message: 'Account is already verified.' });
        }
        
        // CRITICAL CHECK: Ensure the hash field exists before comparing
        if (!user.verificationCode) {
            console.error(`Verification hash missing for ${email}. User may need to resend code.`);
            return res.status(400).json({ message: 'No verification code is pending for this user. Please resend the code.' });
        }

        // 2. Check Expiration
        if (new Date() > user.verificationCodeExpires) {
            return res.status(400).json({ message: 'Verification code has expired. Please request a new one.' });
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
                $set: { 
                    // 🎉 FIXED: Using dot notation to update the nested 'status.isVerified' field
                    'status.isVerified': true 
                },
                // Clear the hash and expiry after successful verification
                $unset: { verificationCode: "", verificationCodeExpires: "" }
            }
        );
        
        console.log(`User ${email} successfully verified.`);
        
        res.status(200).json({ message: 'Account successfully verified. You can now log in.' });

    } catch (error) {
        console.error("User verification error:", error);
        res.status(500).json({ message: 'Server error during verification.' });
    }
});

// =========================================================
// 2. POST /api/users/login (Login) - OPTIMIZED FOR SPEED & PERSISTENCE
// =========================================================
app.post('/api/users/login', async (req, res) => {
    const { email, password, localCartItems } = req.body; 
    try {
        const user = await User.findOne({ email }).select('+password').lean();
                if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        // 2. Check verification status
        if (!user.status.isVerified) {
            return res.status(403).json({ 
                message: 'Account not verified. Please verify your email to log in.',
                needsVerification: true,
                userId: user._id
            });
        }
        // --- 3. 🚀 GENERATE DUAL TOKENS ---
        const tokenPayload = { id: user._id, email: user.email }; 
        const accessToken = generateUserAccessToken(tokenPayload);
        const refreshToken = generateUserRefreshToken(tokenPayload);
        // --- FIX: USE THE CONSISTENT HELPER FUNCTION ---
        // Assuming getCookieOptions(req) relies on the global isProduction variable
        const options = getCookieOptions(req); 
        console.log(`DEBUG LOGIN: Setting cookie with secure: ${options.secure} and sameSite: ${options.sameSite}`);
        // 4. Set the secure HTTP-only Refresh Token cookie
        res.cookie('userRefreshToken', refreshToken, {
            ...options, // Uses httpOnly, secure, and sameSite: 'None'
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });
        // --------------------------------------------------------
        // 5. Merge Cart & Log Activity
        if (localCartItems && Array.isArray(localCartItems) && localCartItems.length > 0) {
            await mergeLocalCart(user._id, localCartItems);
            console.log(`Cart merged for user: ${user._id}`);
        }
        try {
            await logActivity('LOGIN', `User **${user.email}** successfully logged in.`, user._id, { ipAddress: req.ip });
        } catch (logErr) {
            console.warn('Activity logging failed:', logErr);
        }
        // 6. Send the Access Token back to the client
        delete user.password; 
        res.status(200).json({ 
            message: 'Login successful',
            accessToken: accessToken, 
            user: user
        });

    } catch (error) {
        // This is the error caught by the ReferenceError
        console.error("User login error:", error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// 3. GET /api/users/account (Fetch Profile - Protected)
app.get('/api/users/account', verifyUserToken, async (req, res) => {
    try {
        // req.userId is set by verifyUserToken middleware
        const user = await User.findById(req.userId).lean();

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // --- FIX APPLIED HERE: Added the 'address' field ---
        res.status(200).json({
            id: user._id,
            email: user.email,
            profile: user.profile,
            status: user.status,
            membership: user.membership,
            address: user.address // <--- THIS LINE IS ADDED/CORRECTED
        });
        
    } catch (error) {
        console.error("Fetch profile error:", error);
        res.status(500).json({ message: 'Failed to retrieve user profile.' });
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
// 3. POST /api/users/logout (Logout) - NEW
// =========================================================
/**
 * Clears the HTTP-only session cookie, effectively logging the user out.
 * This endpoint is designed to be called by the client's handleLogout function.
 */
app.post('/api/users/logout', (req, res) => {
    try {
        // Use res.clearCookie() to tell the browser to immediately expire the cookie.
        // It's important to use the same cookie name ('outflickzToken').
        // We set the same secure and sameSite flags for maximum compatibility in clearing.
        const isProduction = process.env.NODE_ENV === 'production';

        res.clearCookie('outflickzToken', {
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? 'strict' : 'lax',
        });

        // Send a success response. The client side will handle the redirect.
        res.status(200).json({ 
            message: 'Logout successful. Session cookie cleared.'
        });

    } catch (error) {
        // Even if an error occurs (e.g., in logging), the cookie clearance often still works.
        // We send a success response anyway to ensure the client proceeds with the redirect.
        console.error("Logout error:", error);
        res.status(500).json({ message: 'Server error during logout process.' });
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

app.get('/api/auth/status', verifySessionCookie, (req, res) => {
    // If verifySessionCookie successfully executed, the user is logged in via cookie.
    res.status(200).json({ message: 'Authenticated', isAuthenticated: true });
});

// =========================================================
// NEW: POST /api/orders/calculate-buy-now - Calculate Totals for Single Item (Buy Now/Pre-Order)
// =========================================================
app.post('/api/orders/calculate-buy-now', verifyUserToken, async (req, res) => {
    // This endpoint calculates totals for a single item passed in the request body, 
    // simulating a checkout from the product page (Buy Now).

    // ⭐ CRITICAL FIX: Ensure productType is included as it is required by the OrderItemSchema
    const { productId, name, productType, size, color, price, quantity, imageUrl, variationIndex, variation } = req.body;

    // 1. Basic Input Validation
    if (!productId || !name || !productType || !size || !price || !quantity || price <= 0 || quantity < 1 || variationIndex === undefined || variationIndex === null) {
        return res.status(400).json({ message: 'Missing or invalid item details, including required productType or variation information, for calculation.' });
    }

    // 2. Construct the temporary cart item array, ensuring all necessary fields are present
    // Note: For Cap items, 'size' will contain the variation identifier (e.g., color hex) as fixed on the client-side.
    const temporaryItem = {
        productId,
        name,
        productType, 
        size,
        color: color || 'N/A',
        price, // This price acts as 'priceAtTimeOfPurchase' for the calculation
        quantity,
        imageUrl,
        variationIndex,
        // Use provided variation string, or construct one if only color/index is available
        variation: variation || (color ? `Color: ${color}` : `Var Index: ${variationIndex}`),
    };

    try {
        // 3. Calculate totals using the existing function (which handles shipping/tax rules)
        // Since this is for Buy Now, we pass only the single item in an array.
        const totals = calculateCartTotals([temporaryItem]); 

        // 4. Respond with the single item (in an array) and the calculated totals
        res.status(200).json({
            items: [temporaryItem], // Return the item in an array structure consistent with the cart API
            ...totals,
        });

    } catch (error) {
        console.error('Error calculating Buy Now totals:', error);
        res.status(500).json({ message: 'Failed to calculate order totals.' });
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
        productType,
        size,
        color: color,
        price,
        quantity,
        imageUrl,
        variationIndex,
        variation: variation || (color ? `Color: ${color}` : `Var Index: ${variationIndex}`), 
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

// 7. POST /api/paystack/webhook - Handle Paystack Notifications
app.post('/api/paystack/webhook', async (req, res) => {
    // 1. Verify Webhook Signature (Security Crucial)
    // NOTE: req.body must be the raw buffer for signature calculation!
    const secret = PAYSTACK_SECRET_KEY;
    const hash = crypto.createHmac('sha512', secret)
        .update(req.body) 
        .digest('hex');
    
    if (hash !== req.headers['x-paystack-signature']) {
        console.error('Webhook verification failed: Invalid signature.');
        return res.status(401).send('Unauthorized access.');
    }

    // Convert raw body buffer to JSON object for processing
    // NOTE: If using Express, ensure you have middleware to handle the raw body buffer for verification
    const event = JSON.parse(req.body.toString());

    // 2. Check Event Type
    if (event.event !== 'charge.success') {
        return res.status(200).send(`Event type ${event.event} received but ignored.`);
    }

    const transactionData = event.data;
    const orderReference = transactionData.reference;

    try {
        // 3. Verify Transaction Status with Paystack (Double Check Security)
        const verificationResponse = await fetch(`${PAYSTACK_API_BASE_URL}/transaction/verify/${orderReference}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`,
            }
        });

        const verificationData = await verificationResponse.json();

        if (verificationData.status !== true || verificationData.data.status !== 'success') {
            console.error('Transaction verification failed via API:', verificationData);
            await Order.findOne({ orderReference })
                .then(order => order && Order.findByIdAndUpdate(order._id, { status: 'Verification Failed' }));
            return res.status(200).send('Transaction status not success upon verification.');
        }

        const verifiedAmountKobo = verificationData.data.amount; // amount in kobo
        
        // 4. Find the corresponding Order using the reference
        const order = await Order.findOne({ orderReference });

        if (!order) {
            console.error('Order not found for reference:', orderReference);
            return res.status(404).send('Order not found.');
        }

        // 5. Final Checks (Amount and Status Check)
        if (order.amountPaidKobo !== verifiedAmountKobo) {
            console.error(`Amount mismatch for order ${order._id}. Expected: ${order.amountPaidKobo}, Received: ${verifiedAmountKobo}`);
            await Order.findByIdAndUpdate(order._id, { status: 'Amount Mismatch (Manual Review)' });
            return res.status(200).send('Amount mismatch, requires manual review.');
        }

        if (order.status === 'Paid') {
            return res.status(200).send('Order already processed.');
        }

        // 6. Update Order Status and Clear Cart
        // Perform the update first to persist the crucial status change
        await Order.findByIdAndUpdate(order._id, {
            status: 'Paid',
            paymentTxnId: transactionData.id,
            paidAt: new Date(),
        });

        // Clear the user's cart after successful payment
        await Cart.findOneAndUpdate(
            { userId: order.userId },
            { items: [], updatedAt: Date.now() }
        );
        
        // 7. CRITICAL: SEND CONFIRMATION EMAIL
        // We need the full order object for the email template
        const updatedOrder = await Order.findById(order._id); 
        if (updatedOrder) {
            await sendOrderConfirmationEmail(updatedOrder, 'paid'); 
        } else {
            console.error(`Could not re-fetch order ${order._id} for email.`);
        }

        console.log(`Order ${order._id} successfully marked as Paid, cart cleared, and confirmation email triggered.`);
        
        // 8. Success response to Paystack
        res.status(200).send('Webhook received and order processed successfully.');

    } catch (error) {
        console.error('Internal error processing webhook:', error);
        // It is generally safe to return 200 to the webhook provider even on failure
        // so they stop retrying, provided you log the failure for manual review.
        res.status(500).send('Internal Server Error.'); 
    }
});
// =========================================================
// 8. POST /api/notifications/admin-order-email - Send Notification to Admin
// This is typically called by the client AFTER a successful payment/order creation.
// =========================================================
app.post('/api/notifications/admin-order-email', async (req, res) => {
    
    // The payload is sent as JSON from the client-side 'sendAdminOrderNotification' function
    const { 
        orderId, 
        totalAmount, 
        paymentMethod, 
        shippingDetails, 
        items, 
        adminEmail,
        paymentReceiptUrl, // The URL from B2/DB
        subtotal,
        shippingFee,
        tax
    } = req.body;

    // 1. Basic Validation
    if (!orderId || !totalAmount || !adminEmail || !items || items.length === 0) {
        return res.status(400).json({ message: 'Missing required notification data or order items.' });
    }

    try {
        // --- STEP 1: Prepare Attachments from B2 ---
        const attachments = [];
        let attachmentFileName = null; 
        
        // Only attempt to attach if it's a Bank Transfer AND we have a B2 URL
        if (paymentMethod === 'Bank Transfer' && paymentReceiptUrl) {
            
            try {
                // a. Get the file key (path inside the bucket)
                const fileKey = getFileKeyFromUrl(paymentReceiptUrl);

                if (fileKey) {
                    console.log(`Attempting to download receipt file: ${fileKey}`);

                    // b. Create the GetObject command
                    const getObjectCommand = new GetObjectCommand({
                        Bucket: IDRIVE_BUCKET_NAME,
                        Key: fileKey,
                    });

                    // c. Send the command and get the response stream
                    const response = await s3Client.send(getObjectCommand);

                    // d. Set content type and filename
                    const contentType = response.ContentType || 'application/octet-stream';
                    const keyParts = fileKey.split('/');
                    const suggestedFilename = keyParts[keyParts.length - 1] || 'payment-receipt.jpg'; 
                    
                    // e. Convert stream to Buffer
                    const buffer = await streamToBuffer(response.Body);

                    // f. Add to attachments array (Nodemailer format)
                    attachments.push({
                        filename: suggestedFilename,
                        content: buffer,
                        contentType: contentType,
                    });

                    attachmentFileName = suggestedFilename; 
                    console.log(`Receipt attached successfully: ${suggestedFilename}`);
                } else {
                    console.warn(`[Admin Email] Could not extract file key from URL: ${paymentReceiptUrl}. Skipping receipt attachment.`);
                }
            } catch (downloadError) {
                console.error(`[Admin Email] Failed to download receipt from B2:`, downloadError.message);
            }
        }
        // --- END: STEP 1 ---

        // 2. Format the Email Content (HTML)
        const paymentStatus = (paymentMethod === 'Paystack/Card') ? 'Payment Confirmed (Paystack)' : 'Payment Awaiting Verification (Bank Transfer)';
        
        // --- Item List HTML ---
        const itemDetailsHtml = items.map(item => `
            <tr>
                <td style="padding: 12px 0 12px 0; border-bottom: 1px solid #eee; font-size: 14px; color: #333;">
                    <table border="0" cellpadding="0" cellspacing="0">
                        <tr>
                            <td style="padding-right: 10px;">
                                <img src="${item.imageUrl || 'https://placehold.co/40x40/f7f7f7/999?text=X'}" alt="Product" width="40" height="40" style="display: block; border: 1px solid #ddd; border-radius: 4px;">
                            </td>
                            <td>
                                ${item.name || 'N/A'}
                            </td>
                        </tr>
                    </table>
                </td>
                
                <td style="padding: 12px 0 12px 0; border-bottom: 1px solid #eee; font-size: 12px; color: #555;">
                    <span style="display: block;">Size: <strong>${item.size || 'N/A'}</strong></span>
                    <span style="display: block; margin-top: 2px;">Color: ${item.color || 'N/A'}</span>
                </td>
                
                <td style="padding: 12px 0 12px 0; border-bottom: 1px solid #eee; font-size: 14px; color: #333; text-align: center;">
                    ${item.quantity}
                </td>
                
                <td style="padding: 12px 0 12px 0; border-bottom: 1px solid #eee; font-size: 14px; color: #333; text-align: right;">
                    ₦${(item.price * item.quantity).toLocaleString('en-US', { minimumFractionDigits: 2 })}
                </td>
            </tr>
        `).join('');

        // --- Attachment Confirmation Block ---
        const attachmentConfirmationHtml = attachmentFileName ? `
            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 30px; border-collapse: collapse; border: 1px solid #c0e6c0; border-radius: 4px;">
                <tr>
                    <td style="padding: 15px; background-color: #e0ffe0; font-size: 14px; color: #006400; font-weight: bold; text-align: center;">
                        ✅ Payment Receipt Proof Attached: 
                        <span style="font-weight: normal; color: #333;">${attachmentFileName}</span>
                        <div style="font-size: 12px; color: #555; margin-top: 5px;">
                            (Please check the email attachment for the file.)
                        </div>
                    </td>
                </tr>
            </table>
        ` : (paymentMethod === 'Bank Transfer' ? `
            <p style="margin-top: 30px; font-size: 14px; color: #FF4500; font-weight: bold; text-align: center;">
                ⚠️ Bank Transfer Payment Selected: Receipt attachment failed or URL was missing.
            </p>
        ` : '');

        // --- Financial Breakdown Summary (Using the newly included fields) ---
        const totalAmountNum = parseFloat(totalAmount);
        const subtotalNum = parseFloat(subtotal || (totalAmountNum - (shippingFee || 0) - (tax || 0)));
        const shippingFeeNum = parseFloat(shippingFee || 0);
        const taxNum = parseFloat(tax || 0);

        const financialSummaryHtml = `
            <tr>
                <td style="padding: 10px 0; font-size: 14px; color: #555; width: 50%;">Subtotal:</td>
                <td style="padding: 10px 0; font-size: 14px; color: #000000; text-align: right;">₦${subtotalNum.toLocaleString('en-US', { minimumFractionDigits: 2 })}</td>
            </tr>
            <tr>
                <td style="padding: 5px 0; font-size: 14px; color: #555;">Shipping Fee:</td>
                <td style="padding: 5px 0; font-size: 14px; color: #000000; text-align: right;">₦${shippingFeeNum.toLocaleString('en-US', { minimumFractionDigits: 2 })}</td>
            </tr>
            <tr>
                <td style="padding: 5px 0 20px 0; font-size: 14px; color: #555; border-bottom: 1px dashed #ccc;">Tax:</td>
                <td style="padding: 5px 0 20px 0; font-size: 14px; color: #000000; text-align: right; border-bottom: 1px dashed #ccc;">₦${taxNum.toLocaleString('en-US', { minimumFractionDigits: 2 })}</td>
            </tr>
        `;
        
        // The main HTML structure remains mostly the same, inserting the new breakdown.
        const emailHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>New Outfulickz Order</title>
    <style>
        @media only screen and (max-width: 600px) {
            .container { width: 100% !important; padding: 0 10px !important; }
            .header-logo { width: 150px !important; height: auto !important; }
            .item-table td { display: table-cell !important; }
        }
    </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f4; font-family: Arial, sans-serif;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="table-layout: fixed;">
        <tr>
            <td align="center" style="padding: 20px 0;">
                <table border="0" cellpadding="0" cellspacing="0" width="600" class="container" style="background-color: #ffffff; border: 1px solid #dddddd; border-radius: 8px;">
                    <tr>
                        <td align="center" style="padding: 20px 0 10px 0;">
                            <img src="https://i.imgur.com/6Bvu8yB.png" alt="Outfulickz Logo" class="header-logo" width="180" style="display: block; border: 0; max-width: 180px;">
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 40px 40px 40px;">
                            <h1 style="color: #000000; font-size: 24px; text-align: center; margin-bottom: 20px;">
                                🚨 NEW ORDER PLACED 🚨
                            </h1>
                            <p style="font-size: 16px; color: #333; line-height: 1.5;">
                                A new order has been created and requires immediate attention for fulfillment.
                            </p>
                            
                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 25px; border-collapse: collapse;">
                                <tr>
                                    <td colspan="2" style="font-size: 18px; font-weight: bold; color: #000000; padding-bottom: 10px; border-bottom: 2px solid #000000;">ORDER SUMMARY</td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px 0; font-size: 14px; color: #555; width: 50%;">Order ID:</td>
                                    <td style="padding: 10px 0; font-size: 14px; color: #000000; font-weight: bold; text-align: right;">${orderId}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px 0; font-size: 14px; color: #555;">Payment Method:</td>
                                    <td style="padding: 10px 0; font-size: 14px; color: #000000; text-align: right;">${paymentMethod}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px 0; font-size: 14px; color: #555;">Payment Status:</td>
                                    <td style="padding: 10px 0; font-size: 14px; font-weight: bold; text-align: right; color: ${paymentStatus.includes('Confirmed') ? 'green' : '#FFA500'};">${paymentStatus}</td>
                                </tr>
                                
                                ${financialSummaryHtml}

                                <tr>
                                    <td style="padding: 20px 0 10px 0; font-size: 16px; font-weight: bold; color: #000000;">TOTAL AMOUNT:</td>
                                    <td style="padding: 20px 0 10px 0; font-size: 18px; font-weight: bold; color: #000000; text-align: right;">₦${totalAmountNum.toLocaleString('en-US', { minimumFractionDigits: 2 })}</td>
                                </tr>
                            </table>

                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 30px; border-collapse: collapse;">
                                <tr>
                                    <td colspan="2" style="font-size: 18px; font-weight: bold; color: #000000; padding-bottom: 10px; border-bottom: 2px solid #000000;">SHIPPING DETAILS</td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px 0 5px 0; font-size: 14px; color: #000000; font-weight: bold;" colspan="2">
                                        ${shippingDetails.firstName} ${shippingDetails.lastName}
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding: 5px 0; font-size: 14px; color: #555;" colspan="2">Email: ${shippingDetails.email}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 5px 0 10px 0; font-size: 14px; color: #555; border-bottom: 1px dashed #ccc;" colspan="2">
                                        Address: ${shippingDetails.street}, ${shippingDetails.city}, ${shippingDetails.state}, ${shippingDetails.country} ${shippingDetails.zipCode ? `(${shippingDetails.zipCode})` : ''}
                                    </td>
                                </tr>
                            </table>
                            
                            <table border="0" cellpadding="0" cellspacing="0" width="100%" class="item-table" style="margin-top: 30px; border-collapse: collapse;">
                                <tr>
                                    <td colspan="4" style="font-size: 18px; font-weight: bold; color: #000000; padding-bottom: 10px; border-bottom: 2px solid #000000;">ITEMS ORDERED</td>
                                </tr>
                                
                                <thead>
                                    <tr style="text-align: left; background-color: #f7f7f7;">
                                        <th style="padding: 10px 0; font-size: 12px; color: #555; font-weight: normal; width: 40%;">PRODUCT</th>
                                        <th style="padding: 10px 0; font-size: 12px; color: #555; font-weight: normal; width: 30%;">DETAILS</th>
                                        <th style="padding: 10px 0; font-size: 12px; color: #555; font-weight: normal; width: 10%; text-align: center;">QTY</th>
                                        <th style="padding: 10px 0; font-size: 12px; color: #555; font-weight: normal; width: 20%; text-align: right;">SUBTOTAL</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${itemDetailsHtml}
                                </tbody>
                            </table>
                            
                            ${attachmentConfirmationHtml}

                            <p style="margin-top: 40px; font-size: 12px; color: #777; text-align: center;">
                                This is an automated notification. Please check the order management system for full details and fulfillment.
                            </p>

                        </td>
                    </tr>
                    
                    <tr>
                        <td align="center" style="background-color: #f7f7f7; padding: 15px 40px; border-radius: 0 0 8px 8px;">
                            <p style="margin: 0; font-size: 11px; color: #999;">&copy; ${new Date().getFullYear()} OUTFULICKZ. All rights reserved.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
        `;

        // 3. Send the Email, passing the attachments array
        await sendMail(
            adminEmail,
            `[New Order] #${orderId} - ${paymentStatus}`,
            emailHtml,
            attachments 
        );

        console.log(`Admin notification sent successfully for Order ID: ${orderId} to ${adminEmail}`);
        
        // 4. Send a successful response back to the client
        res.status(200).json({ message: 'Admin notification request received and processing.' });

    } catch (error) {
        console.error('Error in POST /api/notifications/admin-order-email:', error);
        res.status(500).json({ message: 'Failed to dispatch admin email notification due to server error.' });
    }
});

// =========================================================
// 7. POST /api/orders/place/pending - Create a Pending Order (Protected)
// =========================================================
app.post('/api/orders/place/pending', verifyUserToken, (req, res) => {
    
    // 1. Run the Multer middleware to process the form data and file
    singleReceiptUpload(req, res, async (err) => {
        // ... (Multer Error Handling remains the same) ...
        if (err instanceof multer.MulterError) {
             return res.status(400).json({ message: `File upload failed: ${err.message}` });
        } else if (err) {
             console.error('Unknown Multer Error:', err);
             return res.status(500).json({ message: 'Error processing file upload.' });
        }

        const userId = req.userId;
        
        // Extract Form fields 
        const { 
            shippingAddress: shippingAddressString, 
            paymentMethod, 
            totalAmount: totalAmountString, 
            subtotal: subtotalString,
            shippingFee: shippingFeeString,
            tax: taxString,
            orderItems: orderItemsString 
        } = req.body;
        
        const receiptFile = req.file; 
        
        // Convert string fields
        const totalAmount = parseFloat(totalAmountString);
        const subtotal = parseFloat(subtotalString || '0');
        const shippingFee = parseFloat(shippingFeeString || '0');
        const tax = parseFloat(taxString || '0');

        let shippingAddress;

        // --- UPDATED ROBUST PARSING LOGIC ---
        try {
             if (!shippingAddressString || shippingAddressString.trim() === '') {
                 shippingAddress = null; 
             } else {
                 shippingAddress = JSON.parse(shippingAddressString);
             }
        } catch (e) {
             return res.status(400).json({ message: 'Invalid shipping address format. Ensure the address object is stringified correctly.' });
        }
        // --- END: UPDATED ROBUST PARSING LOGIC ---
        
        // 2. Critical Input Validation
        if (!shippingAddress || totalAmount <= 0 || isNaN(totalAmount)) {
             return res.status(400).json({ message: 'Missing shipping address or invalid total amount.' });
        }

        let paymentReceiptUrl = null;
        
        try {
            // ... (Bank Transfer Receipt Upload Logic remains the same) ...
            if (paymentMethod === 'Bank Transfer') {
                if (!receiptFile) {
                    return res.status(400).json({ message: 'Bank payment receipt image is required for a Bank Transfer order.' });
                }
                
                paymentReceiptUrl = await uploadFileToPermanentStorage(receiptFile);
                
                if (!paymentReceiptUrl) {
                    throw new Error("Failed to get permanent URL after B2 upload.");
                }
            }

            // ⭐ 4. RETRIEVE ORDER ITEMS (PRIORITIZE Buy Now Items)
            let finalOrderItems = [];
            let isBuyNowOrder = false;
            
            if (orderItemsString && orderItemsString.trim() !== '') {
                // Scenario 1: Buy Now Checkout
                let rawItems;
                try {
                    rawItems = JSON.parse(orderItemsString);
                } catch (e) {
                    return res.status(400).json({ message: 'Invalid order item list format. Ensure orderItems is stringified correctly.' });
                }
                
                isBuyNowOrder = true;
                
                // -------------------------------------------------------------
                // ⭐ START: BUY NOW ITEM MAPPING & VALIDATION FIX
                // -------------------------------------------------------------
                finalOrderItems = await Promise.all(rawItems.map(async (item) => { // Use Promise.all and async map
                    if (!item.productType || !item.variationIndex) {
                        // Throw immediately if mandatory fields are client-missing
                        throw new Error(`Order item for product ${item.productId} is missing required field: productType or variationIndex.`); 
                    }

                    let correctedType = item.productType;
                    let isTypeValid = !!PRODUCT_MODEL_MAP[item.productType];
                    
                    // Run the correction logic if the type from the client is invalid
                    if (!isTypeValid) { 
                        console.log(`[BUY NOW] Attempting to correct invalid productType: ${item.productType} for ${item.productId}`);
                        
                        // The same collection-lookup logic from the Cart flow
                        for (const type of Object.keys(PRODUCT_MODEL_MAP)) {
                            try {
                                const CollectionModel = getProductModel(type); 
                                const productExists = await CollectionModel.exists({ _id: item.productId });
                                
                                if (productExists) {
                                    correctedType = type;
                                    break;
                                }
                            } catch (error) {
                                console.warn(`Model check failed for type ${type}: ${error.message}`);
                            }
                        }

                        if (correctedType === item.productType) { // If it's still the original invalid type
                             throw new Error(`Product ID ${item.productId} not found in any collection. Cannot place order.`);
                        }
                    }

                    return {
                        ...item, 
                        priceAtTimeOfPurchase: item.price, 
                        productType: correctedType, // Use the corrected or original type
                        variationIndex: item.variationIndex
                    };
                }));
                // -------------------------------------------------------------
                // ⭐ END: BUY NOW ITEM MAPPING & VALIDATION FIX
                // -------------------------------------------------------------

            } else {
                // Scenario 2: Standard Cart Checkout
                const cart = await Cart.findOne({ userId }).lean();

                if (!cart || cart.items.length === 0) {
                    return res.status(400).json({ message: 'Cannot place order: Shopping bag is empty.' });
                }
                
                // Map cart items to OrderItemSchema structure
                finalOrderItems = cart.items.map(item => ({
                    productId: item.productId,
                    name: item.name, 
                    imageUrl: item.imageUrl,
                    productType: item.productType, 
                    quantity: item.quantity,
                    priceAtTimeOfPurchase: item.price, 
                    variationIndex: item.variationIndex,
                    size: item.size,
                    variation: item.variation,
                    color: item.color,
                }));
            }
            
            if (finalOrderItems.length === 0) {
                return res.status(400).json({ message: 'Order item list is empty.' });
            }
            
            // -------------------------------------------------------------
            // ⭐ CRITICAL FIX: VALIDATE AND CORRECT productType (Using getProductModel)
            // This logic is ONLY executed for items from the permanent Cart (Scenario 2).
            // NOTE: The validation for 'Buy Now' is now handled above in Scenario 1.
            // -------------------------------------------------------------
            if (!isBuyNowOrder) {
                for (let item of finalOrderItems) {
                    let isTypeValid = !!PRODUCT_MODEL_MAP[item.productType];

                    if (!isTypeValid) { 
                        console.log(`Attempting to correct invalid productType: ${item.productType} for ${item.productId}`);
                        
                        let correctedType = null;
                        
                        // Iterate through all valid product types from the map
                        for (const type of Object.keys(PRODUCT_MODEL_MAP)) {
                            try {
                                const CollectionModel = getProductModel(type); // Safely get the model
                                
                                // Check if the product ID exists in this collection
                                const productExists = await CollectionModel.exists({ _id: item.productId });
                                
                                if (productExists) {
                                    correctedType = type;
                                    break;
                                }
                            } catch (error) {
                                // If getProductModel throws (e.g., Model not defined), log but continue to next type
                                console.warn(`Model check failed for type ${type}: ${error.message}`);
                            }
                        }

                        if (!correctedType) {
                             // CRITICAL: Product ID not found in any valid collection
                             throw new Error(`Product ID ${item.productId} (Type: ${item.productType}) not found in any collection. Cannot place order.`);
                        }
                        
                        // 1. Update the final order item with the correct type
                        item.productType = correctedType;
                        
                        // 2. Fix the permanent cart data for future checkouts (Optional but recommended)
                        await Cart.findOneAndUpdate(
                            { userId, 'items.productId': item.productId },
                            { '$set': { 'items.$.productType': correctedType } }
                        );
                    }
                }
            }
            // -------------------------------------------------------------

            const orderRef = `REF-${Date.now()}-${userId.substring(0, 5)}`; 

            const newOrder = await Order.create({
                userId: userId,
                // Use the items with the now-corrected productType
                items: finalOrderItems, 
                shippingAddress: shippingAddress,
                totalAmount: totalAmount,
                subtotal: subtotal,
                shippingFee: shippingFee,
                tax: tax,
                status: 'Pending', 
                paymentMethod: paymentMethod,
                orderReference: orderRef, 
                amountPaidKobo: Math.round(totalAmount * 100),
                paymentTxnId: orderRef, 
                paymentReceiptUrl: paymentReceiptUrl,
            });

            // 6. Clear the user's permanent cart ONLY IF it was a standard cart checkout
            if (!isBuyNowOrder) {
                await Cart.findOneAndUpdate(
                    { userId },
                    { items: [], updatedAt: Date.now() }
                );
            }
            
            console.log(`Pending Order created: ${newOrder._id}. Source: ${isBuyNowOrder ? 'Buy Now' : 'Cart'}`);
            
            // ... (Success Response remains the same) ...
            const { firstName, lastName } = shippingAddress;
            res.status(201).json({
                message: 'Pending order placed successfully. Awaiting payment verification.',
                orderId: newOrder._id,
                status: newOrder.status,
                firstName: firstName,
                lastName: lastName,
                ReceiptUrl: paymentReceiptUrl
            });

        } catch (error) {
            console.error('Error placing pending order:', error);
            // Send the specific validation message back to the client if possible
            const userMessage = error.message.includes('validation failed') 
                                ? error.message.split(':').slice(-1)[0].trim() 
                                : 'Failed to create pending order due to a server error.';

            res.status(500).json({ message: userMessage });
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

// 6. GET /api/orders/:orderId (Fetch Single Order Details - Protected)
app.get('/api/orders/:orderId', verifyUserToken, async function (req, res) {
    const orderId = req.params.orderId;
    const userId = req.userId; // Set by verifyUserToken middleware

    if (!orderId) {
        return res.status(400).json({ message: 'Order ID is required.' });
    }
    if (!userId) {
        return res.status(401).json({ message: 'Authentication required.' });
    }

    try {
        // 1. Fetch the specific order document
        const order = await Order.findOne({ 
            _id: orderId, // Find by ID
            userId: userId // AND ensure it belongs to the authenticated user
        })
        // ⭐ FIX: Ensure we select the new financial breakdown fields
        .select('+subtotal +shippingFee +tax')
        .lean();

        if (!order) {
            return res.status(404).json({ message: 'Order not found or access denied.' });
        }

        // 2. Fetch Display Details for each item (Product Name, Image, etc.)
        const productDetailsPromises = order.items.map(async (item) => {
            // Use a copy of the item object for mutation
            let displayItem = { ...item };
            
            // Prioritize saved data for name/image consistency at time of purchase
            if (item.name && item.imageUrl) {
                // If the order item already contains the name and image (which it should now)
                displayItem.sku = `SKU-${item.productType.substring(0,3).toUpperCase()}-${item.size || 'UNK'}`;
                delete displayItem._id; 
                return displayItem;
            }
            
            // Fallback to fetching product details if necessary (e.g., for old orders)
            const Model = productModels[item.productType];
            
            if (!Model) {
                console.warn(`[OrderDetails] Unknown product type: ${item.productType}`);
                displayItem.name = item.name || 'Product Not Found';
                displayItem.imageUrl = item.imageUrl || 'https://via.placeholder.com/150/CCCCCC/FFFFFF?text=Error';
                displayItem.sku = 'N/A';
            } else {
                // Find the original product to get the display details
                const product = await Model.findById(item.productId)
                    .select('name imageUrls') // Only need display data
                    .lean();

                displayItem.name = item.name || (product ? product.name : 'Product Deleted');
                // Use the saved imageUrl if available, otherwise fallback to the first product image
                displayItem.imageUrl = item.imageUrl || (product && product.imageUrls && product.imageUrls.length > 0 ? product.imageUrls[0] : 'https://via.placeholder.com/150/CCCCCC/FFFFFF?text=No+Image');
                displayItem.sku = `SKU-${item.productType.substring(0,3).toUpperCase()}-${item.size || 'UNK'}`;
            }
            
            // Clean up the Mongoose virtual _id field before sending
            delete displayItem._id; 
            
            return displayItem;
        });

        // Resolve all concurrent product detail fetches
        const populatedItems = await Promise.all(productDetailsPromises);
        
        // 3. Construct the final response object, now correctly reading the financial breakdown
        const finalOrderDetails = {
            ...order,
            items: populatedItems,
            // ⭐ FIX/UPDATE: Read the actual stored financial breakdown, falling back to stored data/zero if undefined
            // If subtotal is undefined, approximate it by subtracting fees from the total amount.
            subtotal: order.subtotal !== undefined 
                ? order.subtotal 
                : (order.totalAmount - (order.shippingFee || 0.00) - (order.tax || 0.00)), 
            shippingFee: order.shippingFee || 0.00, 
            tax: order.tax || 0.00 
        };

        // 4. Send the populated details to the frontend
        res.status(200).json(finalOrderDetails);

    } catch (error) {
        console.error('Error fetching order details:', error);
        res.status(500).json({ message: 'Failed to retrieve order details due to a server error.' });
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
    processOrderCompletion,
    inventoryRollback,
    getProductModel,
    app,
    mongoose,
    populateInitialData,
    MONGODB_URI
};