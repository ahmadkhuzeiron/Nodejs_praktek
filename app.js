const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const { Sequelize, DataTypes } = require('sequelize');

// Inisialisasi aplikasi Express
const app = express();

// Konfigurasi Passport.js
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ where: { username } });

      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return done(null, false, { message: 'Incorrect password.' });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findByPk(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

// Konfigurasi Sequelize dan koneksi database
const sequelize = new Sequelize('nodeabsen', 'root', '', {
  dialect: 'mysql',
  host: 'localhost',
});

const User = sequelize.define('User', {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

// Sinkronisasi model dengan database
sequelize.sync({ force: true })
  .then(() => {
    console.log('Database and tables created!');
  })
  .catch((error) => {
    console.error('Error creating database and tables:', error);
  });

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: false,
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.get('/', (req, res) => {
  res.send('<h1>Welcome to SIPKU</h1>');
});

app.get('/login', (req, res) => {
  res.send(`
    <h1>Login</h1>
    ${req.flash('error')}
    <form method="post" action="/login">
      <input type="text" name="username" placeholder="Username" required /><br />
      <input type="password" name="password" placeholder="Password" required /><br />
      <button type="submit">Login</button>
    </form>
    <p>Don't have an account? <a href="/signup">Sign Up</a></p>
  `);
});

app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true,
  })
);

app.get('/signup', (req, res) => {
  res.send(`
    <h1>Sign Up</h1>
    ${req.flash('error')}
    <form method="post" action="/signup">
      <input type="text" name="username" placeholder="Username" required /><br />
      <input type="password" name="password" placeholder="Password" required /><br />
      <button type="submit">Sign Up</button>
    </form>
    <p>Already have an account? <a href="/login">Login</a></p>
  `);
});

app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ where: { username } });

    if (existingUser) {
      req.flash('error', 'Username already exists.');
      return res.redirect('/signup');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, password: hashedPassword });
    res.redirect('/login');
  } catch (error) {
    console.error(error);
    res.redirect('/signup');
  }
});

app.get('/dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`<h1>Welcome, ${req.user.username}!</h1>`);
  } else {
    res.redirect('/login');
  }
});

// Jalankan server
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
