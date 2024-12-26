const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const Sequelize = require('sequelize');
const SequelizeStore = require('connect-session-sequelize')(session.Store);

require('dotenv').config();
const app = express();

// Rate Limiter - Basic Protection
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests. Please try again later.',
});
app.use(limiter);

// Basic Security with Helmet
app.use(helmet());

// CORS Setup (No SameSite)
app.use(cors({
  origin: 'https://balajielectricals.netlify.app',
  methods: ['GET', 'POST'],
  credentials: true
}));

// Body Parsers
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// CSRF Protection Middleware
app.use((req, res, next) => {
    // Only check CSRF for POST, PUT, DELETE (not GET)
    if (['POST', 'PUT', 'DELETE','GET'].includes(req.method) && !req.headers['x-requested-with']) {
        return res.status(403).json({ success: false, message: 'CSRF attack detected' });
    }
    next();
});

// Session Setup (Without SameSite)
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 3600000  // 1 hour
  }
}));

// Sequelize Database Connection
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
  host: process.env.DB_HOST,
  dialect: 'mysql',
  port: process.env.DB_PORT,
  logging: false,
});

// Test Sequelize Connection
sequelize.authenticate()
  .then(() => console.log('Connected to database (Sequelize)'))
  .catch((err) => console.error('DB connection error:', err));

// Session Store
const sessionStore = new SequelizeStore({ db: sequelize });
sessionStore.sync();

// MySQL Pool Connection
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

pool.getConnection((err, connection) => {
  if (err) {
    console.error('Database Connection Failed:', err);
  } else {
    console.log('Connected to MySQL Database');
    connection.release();
  }
});

// SendGrid Setup
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// ------------------- API: Form Submission -------------------
app.post('/submit-solutionForm', [
  body('name').trim().escape().notEmpty().withMessage('Name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('phone').isLength({ min: 10, max: 10 }).isNumeric().trim().withMessage('A valid 10-digit phone number is required'),
  body('description').trim().escape().isLength({ min: 10, max: 100 }).withMessage('Description must be between 10 to 100 characters'),
  body('machine-type').optional().escape(),
], (req, res) => {
  console.log('Form Data:', req.body);

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation Errors:', errors.array());
    return res.status(422).json({ success: false, errors: errors.array() });
  }

  const { formType, name, email, phone, description } = req.body;
  const machineType = req.body['machine-type'] || 'N/A';  // Handle undefined machine type gracefully
  
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

  pool.query(query, values, (err, result) => {
    if (err) {
      console.error('Error inserting data:', err);
      return res.status(500).send({ success: false, message: 'Error saving data.' });
    }

    // Send email to user and admin
    const userMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: email,
      subject: 'Custom Solution Request Received',
      text: `Hello ${name},\n\nThank you for requesting a custom solution.\nWe will get back to you shortly.`,
    };

    const adminMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: process.env.ADMIN_EMAIL,
      subject: 'New Custom Solution Request',
      text: `New Custom Solution request received:\n\nName: ${name}\nDescription: ${description}\nPhone: ${phone}\nEmail: ${email}\nMachine Type: ${machineType}`,
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
  body('message').trim().escape().isLength({ min: 10, max: 100 }),
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
  if (!message || message.trim().length < 10 || message.trim().length > 100) {
    errors.push('message must be between 10 and 100 characters.');
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
    
    

    pool.query(query, values, (err, result) => {
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
  body('subject').trim().escape().isLength({ min: 10, max: 100 }),
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
  if (!subject || subject.trim().length < 10 || subject.trim().length > 100) {
    errors.push('Subject must be between 10 and 100 characters.');
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
    pool.query(query, [name, email, phone, subject], (err, result) => {
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


