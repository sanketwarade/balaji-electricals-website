const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');  // Import SendGrid
const cors = require('cors');
const validator = require('validator');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet'); // New: Secure HTTP headers
require('dotenv').config();


const app = express();


// Define the rate limit rule
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: 'Too many requests from this IP, please try again after 15 minutes.',
});

// Apply to all routes
app.use(limiter);

// Middleware
app.use(helmet());
app.use(cors({
  origin:  'https://darling-conkies-1620b9.netlify.app', // Replace with your actual frontend domain
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MySQL Database Connection
const pool = mysql.createPool({
  host: process.env.DB_HOST, // From environment variables
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test connection on startup
pool.getConnection((err, connection) => {
  if (err) {
    console.error('Database Connection Failed:', err);
  } else {
    console.log('Connected to Database');
    connection.release();
  }
});

module.exports = pool;  // Export pool directly

// Email Setup using environment variables
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// API to handle form submissions
app.post('/submit-solutionform', [
    body('name').trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('phone').isLength({ min: 10, max: 10 }).isNumeric().trim(),
    body('description').optional().escape(),
    body('machine-type').optional().escape(),
], (req, res) => {
    console.log('Form Data:', req.body);

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log('Validation Errors:', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    const { formType, name, email, phone, 'machine-type': machineType, description } = req.body;
    // Make sure machineType is not undefined or null
    if (!machineType) {
        return res.status(400).send({ success: false, message: 'Machine Type is required' });
    }

    const query = `
        INSERT INTO custom_solutions 
        (form_type, name, email, phone, machine_type, description) 
        VALUES (?, ?, ?, ?, ?, ?)
    `;
    
    const values = [
        formType, 
        name, 
        email, 
        phone, 
        machineType, 
        description
    ];
    db.query(query, values, (err, result) => {
        if (err) {
            console.error('Error inserting data:', err);
            return res.status(500).send({ success: false, message: 'Error saving data.' });
        }

        // Send email to user and admin
        const userMail = {
            from: process.env.SENDGRID_SENDER_EMAIL,  // Must be verified on SendGrid
            to: email, // Corrected to use formData.email
            subject: 'Custom Solution Request Received',
            text: `Hello ${name},\n\nThank you for requesting a custom solution.\nWe will get back to you shortly.`
        };

        const adminMail = {
            from: process.env.SENDGRID_SENDER_EMAIL,
            to: process.env.ADMIN_EMAIL,  // Admin email from .env
            subject: 'New custom solution Request',
            text: `New Custom Solution request received:\n\nName: ${name}\nDescription: ${description}\nPhone: ${phone}\nEmail: ${email}\nMachine Type: ${machineType || 'N/A'}`
        };
          // Send emails
          sgMail
          .send(userMail)
          .then(() => {
              console.log('Confirmation email sent to user');
          })
          .catch((error) => {
              console.error('Error sending email to user:', error);
          });

      sgMail
          .send(adminMail)
          .then(() => {
              console.log('Notification email sent to admin');
          })
          .catch((error) => {
              console.error('Error sending email to admin:', error);
          });
        res.status(200).send({ success: true, message: 'Form submitted successfully!' });
    });
});



// POST endpoint to handle form submission
app.post('/submit-quoteForm', [
  body('name').trim().escape().isLength({ min: 2, max: 50 }),
  body('email').isEmail().normalizeEmail(),
  body('contact').isMobilePhone('en-IN'),
  body('message').trim().escape().isLength({ min: 10, max: 200 }),
],
  (req, res) => {
    const { name, company, contact, email, machines, message } = req.body;
    // Log received data for debugging
    console.log('Received Data:', req.body);  // Log received data on backend
     // Ensure company is not undefined or null
     const companyValue = company || '';  // Default to empty string if company is undefined or empty


  // Initialize an error message array
  let errors = [];
   // **Validate Name**
   if (!name || name.trim() === '') {
    errors.push('Name is required.');
  } else if (!validator.isLength(name, { min: 2, max: 50 })) {
    errors.push('Name must be between 2 and 50 characters.');
  }

  // **Validate Email**
  if (!email || !validator.isEmail(email)) {
    errors.push('A valid email address is required.');
  }

  // **Validate Phone**
  if (!contact || !validator.isMobilePhone(contact, 'en-IN')) {
    errors.push('A valid 10-digit phone number is required.');
  }

  // **Validate Subject**
  if (!message || message.trim().length < 10 || message.trim().length > 200) {
    errors.push('message must be between 10 and 200 characters.');
  }

  // If there are validation errors, return them
  if (errors.length > 0) {
    return res.status(400).json({ success: false, errors });
  }

  // **Sanitize Inputs**
  const sanitizedInputs = {
    name: validator.escape(name),
    email: validator.escape(email),
    phone: validator.escape(contact),
    message: validator.escape(message)
  };



    // Save the data to MySQL
    const query = 'INSERT INTO quote_requests (name, company, contact, email, machines, message) VALUES (?, ?, ?, ?, ?, ?)';
    
    const values = [name, company, contact, email, JSON.stringify(machines), message];
    
    

    db.query(query, values, (err, result) => {
        if (err) {
            console.error('Error inserting data into database:', err);
            return res.status(500).json({ message: 'Error saving data to database' });
        }

        // Send email to user (confirmation)
        const userMail = {
            from:process.env.SENDGRID_SENDER_EMAIL,  // Must be verified on SendGrid
            to: email,
            subject: 'Quote Request Received',
            text: `Hello ${name},\n\nThank you for requesting a quote. Here are the details we received:\n\nMachines/Parts: ${machines.join(', ')}\nMessage: ${message}\n\nWe will get back to you shortly.`
        };

        // Send email to admin (quote details)
        const adminMail = {
            from: process.env.SENDGRID_SENDER_EMAIL,
            to: process.env.ADMIN_EMAIL,  // Admin email address
            subject: 'New Quote Request',
            text: `New quote request received:\n\nName: ${name}\nCompany: ${company}\nContact: ${contact}\nEmail: ${email}\nMachines/Parts: ${machines.join(', ')}\nMessage: ${message}`
        };

        // Send emails
        sgMail
        .send(userMail)
        .then(() => {
            console.log('Confirmation email sent to user');
        })
        .catch((error) => {
            console.error('Error sending email to user:', error);
        });

    sgMail
        .send(adminMail)
        .then(() => {
            console.log('Notification email sent to admin');
        })
        .catch((error) => {
            console.error('Error sending email to admin:', error);
        });

        

        // Send success response
        res.status(200).json({ message: 'Quote request submitted successfully' });
    });
});

// Route to handle form submission
app.post('/submit-Enquiryform', [
  body('name').trim().escape().isLength({ min: 2, max: 50 }),
  body('email').isEmail().normalizeEmail(),
  body('phone').isMobilePhone('en-IN'),
  body('subject').trim().escape().isLength({ min: 10, max: 200 }),
],
  (req, res) => {
    const { name, email, phone, subject } = req.body;
    console.log('Request received:', req.body);

    let errors = [];

  // **Validate Name**
  if (!name || name.trim() === '') {
    errors.push('Name is required.');
  } else if (!validator.isLength(name, { min: 2, max: 50 })) {
    errors.push('Name must be between 2 and 50 characters.');
  }

  // **Validate Email**
  if (!email || !validator.isEmail(email)) {
    errors.push('A valid email address is required.');
  }

  // **Validate Phone**
  if (!phone || !validator.isMobilePhone(phone, 'en-IN')) {
    errors.push('A valid 10-digit phone number is required.');
  }

  // **Validate Subject**
  if (!subject || subject.trim().length < 10 || subject.trim().length > 200) {
    errors.push('Subject must be between 10 and 200 characters.');
  }

  // If there are validation errors, return them
  if (errors.length > 0) {
    return res.status(400).json({ success: false, errors });
  }

  // **Sanitize Inputs**
  const sanitizedInputs = {
    name: validator.escape(name),
    email: validator.escape(email),
    phone: validator.escape(phone),
    subject: validator.escape(subject)
  };
  
    // SQL query to insert form data into the database
    const query = `INSERT INTO enquiries (name, email, phone, subject) VALUES (?, ?, ?, ?)`;
    const values = [
        name, 
        email, 
        phone, 
        subject
    ];
    db.query(query, [name, email, phone, subject], (err, result) => {
      if (err) {
        console.error('Error inserting data:', err);
        return res.status(500).send('Error saving data');
      }
  
      // Send confirmation email to the user
      const userMail = {
        from: process.env.SENDGRID_SENDER_EMAIL,  // Must be verified on SendGrid
        to: email,
        subject: 'Thank you for your enquiry!',
        text: `Dear ${name},\n\nThank you for reaching out to BALAJI ELECTRICALS. We will get back to you soon.\n\nBest regards,\nBALAJI ELECTRICALS`
      };
  
  
      // Send notification email to admin
      const adminMail = {
        from: process.env.SENDGRID_SENDER_EMAIL,
        to: process.env.ADMIN_EMAIL,
        subject: 'New Enquiry Received',
        text: `New enquiry from ${name}.\n\nDetails:\nName: ${name}\nEmail: ${email}\nPhone: ${phone}\nSubject: ${subject}`
      };

      // Send emails
      sgMail
      .send(userMail)
      .then(() => {
          console.log('Confirmation email sent to user');
      })
      .catch((error) => {
          console.error('Error sending email to user:', error);
      });

  sgMail
      .send(adminMail)
      .then(() => {
          console.log('Notification email sent to admin');
      })
      .catch((error) => {
          console.error('Error sending email to admin:', error);
      });
  
      
        res.status(200).send('Enquiry submitted successfully');
      });
    });
  
// Start seerver

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});


