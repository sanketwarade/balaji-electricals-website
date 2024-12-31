const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const csrf = require('csrf');  // CSRF token library for form 1 and 2
const sgMail = require('@sendgrid/mail');  // Import SendGrid
const cors = require('cors');
const validator = require('validator');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet'); // New: Secure HTTP headers
const rateLimit = require('express-rate-limit');
const path = require('path');
const cookieParser = require('cookie-parser');
const fs = require('fs');
require('dotenv').config();

const app = express();
app.use(express.json());

// Define the rate limit rule
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 80, // Limit each IP to 100 requests per window
  message: 'Too many requests from this IP, please try again after 15 minutes.',
});

// Apply to all routes
app.use(limiter);
// Enable trust proxy in Express
app.set('trust proxy', 1); // This allows Express to trust the X-Forwarded-For header

app.use(bodyParser.json());
app.use(cookieParser())

app.use(express.static(path.join(__dirname, '../frontend')));



app.use(bodyParser.urlencoded({ extended: true }));

app.use(helmet())
const tokens = new csrf(); // CSRF Instance for forms 1 and 2
// CSRF protection middleware
// Allow requests only from your frontend
const corsOptions = {
  origin: 'https://balajielectricals.netlify.app',  // Allow your frontend
  methods: ['GET', 'POST'],  // Allow specific methods
  allowedHeaders: ['Content-Type', 'X-CSRF-TOKEN'],  // Allow headers
  credentials: true  // Allow cookies or sessions to be sent
};
app.use(cors(corsOptions));
//form 3 route 
// CSRF Token Handling for 3rd Form




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

// Create the MySQL session store using the pool
const sessionStore = new MySQLStore({}, pool);
module.exports = pool;  // Export pool directly
app.use(session({
  secret: process.env.SESSION_SECRET,  // Replace with a secure secret
  resave: false,
  store: sessionStore,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,  // Session valid for 1 day
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',  // Secure cookie in production
    sameSite: 'None'    // Ensure CSRF cookie can work cross-origin
  }
}));
// CORS Configuration
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://balajielectricals.netlify.app');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-TOKEN');
  next();
});
app.get('/', (req, res) => {
  res.send('Welcome to Balaji Electricals!');
});
// CSRF Token Generation Endpoint
// CSRF Token Generation Endpoint (Keep only this one)
// CSRF Token Generation Endpoint (Generate token but keep secret consistent)
app.get('/csrf-token', (req, res) => {
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = tokens.secretSync();  // Generate if missing
  }
  const csrfToken = tokens.create(req.session.csrfSecret);  // Create from existing secret
  res.json({ csrfToken, expiresIn: req.session.cookie.maxAge / 1000 });
});

// Error Handling for CSRF Mismatch
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    console.warn("CSRF token mismatch, generating new token...");
    if (!req.session.csrfSecret) {
      req.session.csrfSecret = tokens.secretSync();
    }
    const newCsrfToken = tokens.create(req.session.csrfSecret);
    res.status(403).json({
      message: 'CSRF token expired. Please try again.',
      csrfToken: newCsrfToken
    });
  } else {
    next(err);
  }
});

// CSRF Token Handling for Forms
app.get('/quoteForm', (req, res) => {
  try {
    if (!req.session.csrfSecret) {
      req.session.csrfSecret = tokens.secretSync();
    }
    const csrfToken = tokens.create(req.session.csrfSecret);  // Generate token
    const htmlContent = fs.readFileSync(path.join(__dirname, 'Frontend/get-quote.html'), 'utf-8');
    res.json({
      csrfToken,
      htmlContent
    });
  } catch (error) {
    console.error("Error in /quoteForm route:", error);
    res.status(500).send('Internal Server Error');
  }
});


// Email Setup using environment variables
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

//post method  for custom-solution
app.post('/submit-solutionform', [
  body('name').trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('phone').isLength({ min: 10, max: 10 }).isNumeric().trim(),
  body('description').isLength({min:10, max:100}).trim(),
  body('machine-type').isLength({min:3, max:50}).trim(),
], (req, res) => {
  console.log('Form Data:', req.body);
  const csrfToken = req.headers['x-csrf-token'];
  const csrfSecret = req.session.csrfSecret;
  console.log('Received CSRF token:', csrfToken);  // Log received token
  console.log('Stored CSRF secret:', csrfSecret);  // Log stored token

if (!csrfToken) {
  return res.status(400).json({ error: 'CSRF token missing' });
}
if (!csrfSecret || !tokens.verify(csrfSecret, csrfToken)) {
  console.log('CSRF verification failed');
  return res.status(403).json({ error: 'Invalid CSRF token' });
}
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation Errors:', errors.array());
    return res.status(400).json({ errors: errors.array() });
  }
  // Destructure only once to avoid redeclaration issues
  const { formType, name, email, phone,  'machine-type': machineType, description } = req.body;
  if (!name || !email || !phone || !machineType || !description) {
    return res.status(400).json({ error: 'All fields are required' });
}
  // Ensure that machineType is not undefined or null
  if (!machineType) {
    return res.status(400).send({ success: false, message: 'Machine Type is required' });
  }
  // Sanitize Inputs
  const sanitizedInputs = {
    name: validator.escape(name),
    email: validator.escape(email),
    phone: validator.escape(phone),
    subject: validator.escape(machineType),
    description: validator.escape(description)
  };
  const query = `'INSERT INTO custom_solutions (form_type, name, email, phone, machine_type, description) VALUES (?, ?, ?, ?, ?, ?);''
  `
  const values = [sanitizedInputs.name, sanitizedInputs.email, sanitizedInputs.phone, sanitizedInputs.machineType,sanitizedInputs.description];
  pool.execute(
    'INSERT INTO custom_solutions (form_type, name, email, phone, machine_type, description) VALUES (?, ?, ?, ?, ?, ?)',
    [formType, name, email, phone, machineType, description],
    (query, values,(err, result) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      console.log('Data inserted into database:', result);
    }
  )
  );
    const userMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,  // Must be verified on SendGrid
      to: sanitizedInputs.email, 
      subject: 'Custom Solution Request Received',
      text: `Hello ${name},\n\nThank you for requesting a custom solution.\nWe will get back to you shortly.`
    };
    const adminMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: process.env.ADMIN_EMAIL,  
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

// POST endpoint to handle form submission (Quote Form) this is the form 3
app.post('/submit-quoteForm', [ //form 3
  body('name').trim().escape().isLength({ min: 3, max: 50 }),
  body('email').isEmail().normalizeEmail(),
  body('contact').isLength({ min: 10, max: 10 }).isNumeric().trim(),
  body('message').trim().escape().isLength({ min: 10, max: 100 }),
  body('company').trim().escape().isLength({min: 3, max: 50}),
  body('machines').trim().escape().isIn(['Mig Welding Machine', 'Tig Welding Machine', 'SPM Welding Machine', 'Rotary Positioner','X-Y Linear Slides','Spare Parts','Control Panels']) .withMessage('Invalid machine selection.')
], 
  (req, res) => {
    // CSRF Token Handling
  const csrfToken = req.body.csrf || req.headers['x-csrf-token'];  // Check both body and headers  // Fetch the CSRF token from the body
  const csrfSecret = req.session.csrfSecret;  // Session CSRF Secret
  
  // Log received data for debugging
  console.log('Received Data:', req.body);
  console.log('Received CSRF Token:', csrfToken);

  // Regenerate CSRF token on each request for extra security
  req.session.csrfSecret = tokens.secretSync();

  // CSRF Token Validation
  if (!csrfToken) {
    return res.status(400).json({ error: 'CSRF token missing' });
  }
  
  // CSRF Secret Verification
  if (!csrfSecret || !tokens.verify(csrfSecret, csrfToken)) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
    console.log('Validation Errors:', errors.array());
    return res.status(400).json({ errors: errors.array() });
    }
    const { formType, name, company, contact, email, machines, message } = req.body;
    // Validate and process the data
    if (!name || !email || !contact || !company || !machines || !message) {
      return res.status(400).json({ error: 'All fields are required' });
  }
  // Sanitize Inputs
  const sanitizedInputs = {
    name: validator.escape(name),
    email: validator.escape(email),
    phone: validator.escape(contact),
    message: validator.escape(message),
    company:validator.escape(company)
  };

  // Save data to MySQL
  const query = 'INSERT INTO quote_requests (form_type, name, company, contact, email, machines, message) VALUES (?, ?, ?, ?, ?, ?, ?)';
  const values = [formType, sanitizedInputs.name, sanitizedInputs.company, sanitizedInputs.contact, sanitizedInputs.email, JSON.stringify(machines), sanitizedInputs.message];
  pool.execute(
    'INSERT INTO quote_requests (form_type, name, company, contact, email, machines, message) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [formType, name, email, contact, company, machines, message],
    (query, values, (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    console.log('Data inserted into database:', result);
    }
  ));
    // Send email to user (confirmation)
    const userMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: sanitizedInputs.email,
      subject: 'Quote Request Received',
      text: `Hello ${sanitizedInputs.name},\n\nThank you for requesting a quote. Here are the details we received:\n\nMachines/Parts: ${machines.join(', ')}\nMessage: ${sanitizedInputs.message}\n\nWe will get back to you shortly.`,
      };
    // Send email to admin (quote details)
    const adminMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: process.env.ADMIN_EMAIL,
      subject: 'New Quote Request',
      text: `New quote request received:\n\nName: ${sanitizedInputs.name}\nCompany: ${sanitizedInputs.company}\nContact: ${sanitizedInputs.contact}\nEmail: ${sanitizedInputs.email}\nMachines/Parts: ${machines.join(', ')}\nMessage: ${sanitizedInputs.message}`,
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
      res.status(200).send({ success: true, message: 'Quote Request Submitted Successfully!' });
  });

// POST endpoint to handle form submission (Enquiry Form)
app.post('/submit-Enquiryform', [
  body('name').trim().escape().isLength({ min: 2, max: 50 }),
  body('email').isEmail().normalizeEmail(),
  body('phone').isMobilePhone('en-IN'),
  body('subject').trim().escape().isLength({ min: 10, max: 200 }),
],  (req, res) => {
  console.log('Received Data:', req.body);
  const csrfToken = req.headers['x-csrf-token'];
    const csrfSecret = req.session.csrfSecret;
    console.log('Received CSRF token:', csrfToken);  // Log received token
    console.log('Stored CSRF secret:', csrfSecret);  // Log stored token
    console.log('Received CSRF token:', csrfToken);  // Log received token
  console.log('Stored CSRF secret:', csrfSecret); 
    
    if (!csrfToken) {
      return res.status(400).json({ error: 'CSRF token missing' });
    }
    
    if (!csrfSecret || !tokens.verify(csrfSecret, csrfToken)) {
      console.log('CSRF verification failed');
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    

    const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation Errors:', errors.array());
    return res.status(400).json({ errors: errors.array() });
  }
  
  const { formType, name, email, phone, subject } = req.body;

  // Sanitize Inputs
  const sanitizedInputs = {
    name: validator.escape(name),
    email: validator.escape(email),
    phone: validator.escape(phone),
    subject: validator.escape(subject),
  };

  
  // Save data to MySQL
  const query = 'INSERT INTO enquiries (form_type, name, email, phone, subject) VALUES (?, ?, ?, ?, ?)';
  const values = [sanitizedInputs.name, sanitizedInputs.email, sanitizedInputs.phone, sanitizedInputs.subject];

  pool.execute(
    'INSERT INTO enquiries (form_type, name, email, phone, subject) VALUES (?, ?, ?, ?, ?)',
    [formType, name, email, phone,  subject],
    (query, values,(err, result) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      console.log('Data inserted into database:', result);
    }
  )
  );

    // Send confirmation email to the user
    const userMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: sanitizedInputs.email,
      subject: 'Thank you for your enquiry!',
      text: `Dear ${name},\n\nThank you for reaching out to BALAJI ELECTRICALS. We will get back to you soon.\n\nBest regards,\nBALAJI ELECTRICALS`,
    };

    // Send notification email to admin
    const adminMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: process.env.ADMIN_EMAIL,
      subject: 'New Enquiry Received',
      text: `New enquiry from ${name}.\n\nDetails:\nName: ${name}\nEmail: ${email}\nPhone: ${phone}\nSubject: ${subject}`,
    };

    // Send emails
    sgMail.send(userMail).then(() => {
      console.log('Confirmation email sent to user');
    }).catch((error) => {
      console.error('Error sending email to user:', error);
    });

    sgMail.send(adminMail).then(() => {
      console.log('Notification email sent to admin');
    }).catch((error) => {
      console.error('Error sending email to admin:', error);
    });

    // Send success response
    res.status(200).send('Enquiry submitted successfully');
  });



// Maintenance Mode Check
const isMaintenance = process.env.MAINTENANCE_MODE === 'false';

app.use((req, res, next) => {
  if (isMaintenance && req.path !== '/maintenance.html' && !req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, 'BALAJI ELECTRICALS', 'Frontend', 'maintenance.html'));
  } else {
    next();
  }
});

// HTML Page Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'BALAJI ELECTRICALS', 'Frontend', 'maintenance.html'));
});

// 404 Page
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'BALAJI ELECTRICALS', 'Frontend', '404.html'));
});

// Handle Email Submissions (Async/Await for Pool)
app.post('/notify', async (req, res) => {
  const { email } = req.body;

  if (email && validateEmail(email)) {
    const query = `INSERT INTO notify_emails (email) VALUES (?) 
                   ON DUPLICATE KEY UPDATE email=email`;

    try {
      const [result] = await pool.execute(query, [email]);
      res.status(200).send({ message: 'You will be notified!' });
    } catch (err) {
      console.error('Failed to insert email:', err);
      res.status(500).send({ error: 'Database error' });
    }
  } else {
    res.status(400).send({ error: 'Invalid email address' });
  }
});

// Validate Email
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase());
}

// Send Notifications 
async function sendNotifications() {
  const selectQuery = 'SELECT email FROM notify_emails WHERE notified = false';

  try {
    const [results] = await pool.execute(selectQuery);

    const message = {
      from: process.env.ADMIN_EMAIL,
      subject: 'We are Back Online!',
      text: 'Hello! Balaji Electricals is back online. Thank you for your patience.',
      html: `<p>Hello! <b>Balaji Electricals</b> is now back online. Thank you for waiting!</p>`,
    };

    for (const row of results) {
      message.to = row.email;
      try {
        await sgMail.send(message);
        console.log(`Email sent to ${row.email}`);
        await markAsNotified(row.email);
      } catch (error) {
        console.error(`Failed to send email to ${row.email}:`, error.toString());
      }
    }
  } catch (err) {
    console.error('Failed to fetch emails:', err);
  }
}

// Mark Emails as Notified (Async)
async function markAsNotified(email) {
  const updateQuery = 'UPDATE notify_emails SET notified = true WHERE email = ?';

  try {
    await pool.execute(updateQuery, [email]);
  } catch (err) {
    console.error(`Failed to update notified status for ${email}`, err);
  }
}

// Countdown Timer for Sending Notifications
const maintenanceEndDate = new Date("2024-12-29T01:03:59");
const timeUntilEnd = maintenanceEndDate - new Date();

if (timeUntilEnd > 0) {
  setTimeout(() => {
    sendNotifications();
    console.log('Maintenance ended. Notifications sent.');
  }, timeUntilEnd);
}


// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});




