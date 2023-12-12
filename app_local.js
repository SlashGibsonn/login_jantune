const express = require('express');
const bcrypt = require('bcrypt');
const mysql = require('mysql');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
const { error } = require('console');
const jwt = require('jsonwebtoken');

dotenv.config({ path: './.env' });
const app = express();
app.use(express.json());

const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE,
});

db.connect((error) => {
    if (error) {
        console.log(error);
    } else {
        console.log('Connected to MySQL');
    }
});

// const transporter = nodemailer.createTransport({
//     service: 'gmail',
//     auth: {
//         user: process.env.EMAIL_USER,
//         pass: process.env.EMAIL_PASSWORD,
//     },
// });

// nyoba array
// const users = [];
const JWT_SECRET = process.env.JWT_SECRET;

function generateToken(userId) {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '5m' });
}

const fileStorageEngine = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, './images');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '..' + file.originalname);
    },
});

const upload = multer({ storage: fileStorageEngine });

function verifyToken(req, res, next) {
    const token = req.header('Authorization');

    if (!token) {
        return res.status(401).send('Access denied. No token provided.');
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error('Error verifying token:', err);
            return res.status(401).send('Invalid token.');
        }

        req.userId = decoded.userId;
        next();
    });
}

app.get('/users', (req, res) => {
    db.query('SELECT name,email,id FROM users', (error, result) => {
        if (error) {
            console.log(error);
            res.status(500).send('Internal Server Error');
        } else {
            res.json(result);
        }
    });
});

app.get('/users/:userId', (req,res)=> {
    const userId = req.params.userId;
    db.query('SELECT name,email,id FROM users WHERE id = ?',userId, (error,result)=>{
        if(error){
            console.log(error);
            res.status(500).send('Internal Server Error');
        }else{
            res.json(result);
        }
    });
});

app.post('/users', async (req, res) => {
    try {
        const existingUser = await getUserByEmail(req.body.email);

        if (existingUser) {
            res.status(400).send('Email is already registered');
        } else {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(req.body.password, salt);

            const newUser = {
                name: req.body.name,
                email: req.body.email,
                password: hashedPassword,
                phone_number: req.body.phone_number,
            };

            db.query('INSERT INTO users SET ?', newUser, (error, result) => {
                if (error) {
                    console.log(error);
                    res.status(500).send('Internal Server Error');
                } else {
                    console.log(result);
                    res.status(201).send('User Created');
                }
            });
        }
    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
});

async function getUserByEmail(email) {
    return new Promise((resolve, reject) => {
        db.query('SELECT * FROM users WHERE email = ?', email, (error, results) => {
            if (error) {
                reject(error);
            } else {
                resolve(results[0]);
            }
        });
    });
} 

app.post('/users/login', async (req, res) => {
    const email = req.body.email;
    db.query('SELECT * FROM users WHERE email = ?', email, async (error, results) => {
        if (error) {
            console.log(error);
            res.status(500).send('Internal Server Error');
        } else if (results.length > 0) {
            const user = results[0];
            try {
                if (await bcrypt.compare(req.body.password, user.password)) {
                    // mbuat token JWT
                    const token = generateToken(user.id);
                    res.json({ token });
                } else {
                    res.status(401).send('Authentication failed');
                }
            } catch (error) {
                console.log(error);
                res.status(500).send('Internal Server Error');
            }
        } else {
            res.status(400).send('User not found');
        }
    });
});
app.delete('/users/:userId', verifyToken,(req, res) => {
    const userId = req.params.userId;

    db.query('DELETE FROM users WHERE id = ?', userId, (error, result) => {
        if (error) {
            console.log(error);
            res.status(500).send('Internal Server Error');
        } else if (result.affectedRows > 0) {
            res.send(`User with ID ${userId} deleted successfully`);
        } else {
            res.status(404).send(`User with ID ${userId} not found`);
        }
    });
});

app.post('/users/forgot-password',verifyToken, async (req, res) => {
    const email = req.body.email;

    try {
        const user = await getUserByEmail(email);

        if (!user) {
            return res.status(404).send('User not found');
        }

        // Gtoken digenerate
        const token = crypto.randomBytes(20).toString('hex');

        // update token ke database
        db.query('UPDATE users SET reset_token = ? WHERE id = ?', [token, user.id], (error, result) => {
            if (error) {
                console.log(error);
                return res.status(500).send('Internal Server Error');
            }

            // sending lokal dengan token
            console.log('Reset Token:', token);
            res.send('Password reset instructions simulated');
        });
    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
});


app.post('/users/reset-password/:token',verifyToken, async (req, res) => {
    const token = req.params.token;
    const newPassword = req.body.newPassword;

    try {
        const user = await getUserByResetToken(token);

        if (!user) {
            return res.status(400).send('Invalid or expired token');
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        db.query('UPDATE users SET password = ?, reset_token = NULL WHERE id = ?', [hashedPassword, user.id], (error, result) => {
            if (error) {
                console.log(error);
                res.status(500).send('Internal Server Error');
            } else {
                res.send('Password reset successfully');
            }
        });
    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
});

async function getUserByResetToken(token) {
    return new Promise((resolve, reject) => {
        db.query('SELECT * FROM users WHERE reset_token = ?', token, (error, results) => {
            if (error) {
                reject(error);
            } else {
                resolve(results[0]);
            }
        });
    });
}

app.put('/users/update-profile/:userId', verifyToken, upload.single('image'), async (req, res) => {
    try {
        const userId = req.params.userId;
        const user = await getUserById(userId);

        if (!user) {
            return res.status(404).send('User not found');
        }

        const name = req.body.name;
        const phoneNumber = req.body.phone_number;

        // Handle image uploadd
        if (req.file) {
            const imagePath = req.file.path;
            db.query('UPDATE users SET user_image = ? WHERE id = ?', [imagePath, userId], (error, result) => {
                if (error) {
                    console.log(error);
                    res.status(500).send('Internal Server Error');
                    return;
                }
            });
        }

        // Handle name update
        if (name) {
            db.query('UPDATE users SET name = ? WHERE id = ?', [name, userId], (error, result) => {
                if (error) {
                    console.log(error);
                    res.status(500).send('Internal Server Error');
                    return;
                }
            });
        }

        // Handle phone number update
        if (phoneNumber) {
            if (!/^\d+$/.test(phoneNumber)) {
                return res.status(400).send('Invalid phone number. Only numeric characters are allowed.');
            }
            db.query('UPDATE users SET phone_number = ? WHERE id = ?', [phoneNumber, userId], (error, result) => {
                if (error) {
                    console.log(error);
                    res.status(500).send('Internal Server Error');
                    return;
                }
            });
        }

        res.send('Profile updated');
    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
});

app.delete('/users/delete-image/:userId', verifyToken,async (req, res) => {
    const userId = req.params.userId;

    // Verifikasi apakah user dengan ID tersebut ada
    const user = await getUserById(userId);

    if (!user) {
        return res.status(404).send('User not found');
    }

    // untuk remove profile user
    db.query('UPDATE users SET user_image = NULL WHERE id = ?', userId, (error, result) => {
        if (error) {
            console.log(error);
            res.status(500).send('Internal Server Error');
        } else {
            res.send('Profile image removed');
        }
    });
});

app.delete('/users/delete-phone/:userId', verifyToken,async (req, res) => {
    const userId = req.params.userId;

    // Verifikasi apakah user dengan ID tersebut ada
    const user = await getUserById(userId);

    if (!user) {
        return res.status(404).send('User not found');
    }

    // untuk remove phone_number isinya
    db.query('UPDATE users SET phone_number = NULL WHERE id = ?', userId, (error, result) => {
        if (error) {
            console.log(error);
            res.status(500).send('Internal Server Error');
        } else {
            res.send('Phone number removed');
        }
    });
});

async function getUserById(userId) {
    return new Promise((resolve, reject) => {
        db.query('SELECT * FROM users WHERE id = ?', userId, (error, results) => {
            if (error) {
                reject(error);
            } else {
                resolve(results[0]);
            }
        });
    });
}

app.get('/protected-route', verifyToken, (req, res) => {
    // If the token is valid, this route handler will be executed
    res.send('You have access to the protected route.');
});

process.on('SIGINT', () => {
    db.end((err) => {
        console.log('Database connection closed.');
        process.exit(err ? 1 : 0);
    });
});

app.listen(8000, () => {
    console.log('Server started on port 8000');
});