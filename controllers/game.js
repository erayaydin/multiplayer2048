const async = require('async');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');

/**
 * GET /game
 * Game screen.
 */
exports.index = (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  res.render('game/index', {
    title: 'Oyun'
  });
};

/**
 * POST /login
 * Sign in using email and password.
 */
exports.doLogin = (req, res, next) => {
  req.assert('email', 'E-posta geçerli değil').isEmail();
  req.assert('password', 'Şifre boş bırakılamaz').notEmpty();
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/login');
  }

  passport.authenticate('local', (err, user, info) => {
    if (err) { return next(err); }
    if (!user) {
      req.flash('errors', info);
      return res.redirect('/login');
    }
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      req.flash('success', { msg: 'Başarılı! Giriş yaptınız.' });
      res.redirect(req.session.returnTo || '/');
    });
  })(req, res, next);
};

/**
 * GET /logout
 * Log out.
 */
exports.logout = (req, res) => {
  req.logout();
  res.redirect('/');
};

/**
 * GET /signup
 * Signup page.
 */
exports.register = (req, res) => {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('user/register', {
    title: 'Hesap Oluştur'
  });
};

/**
 * POST /signup
 * Create a new local account.
 */
exports.doRegister = (req, res, next) => {
  req.assert('email', 'E-posta geçerli değil').isEmail();
  req.assert('password', 'Şifreniz en az 4 karakter uzunluğunda olmalıdır').len(4);
  req.assert('confirmPassword', 'Şifreler uyuşmuyor').equals(req.body.password);
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/register');
  }

  const user = new User({
    email: req.body.email,
    password: req.body.password
  });

  User.findOne({ email: req.body.email }, (err, existingUser) => {
    if (existingUser) {
      req.flash('errors', { msg: 'Bu e-posta adresi kullanılmaktadır.' });
      return res.redirect('/register');
    }
    user.save((err) => {
      if (err) { return next(err); }
      req.logIn(user, (err) => {
        if (err) {
          return next(err);
        }
        res.redirect('/');
      });
    });
  });
};

/**
 * GET /account
 * Profile page.
 */
exports.account = (req, res) => {
  res.render('user/profile', {
    title: 'Hesap Yönetimi'
  });
};

/**
 * POST /account/profile
 * Update profile information.
 */
exports.updateProfile = (req, res, next) => {
  req.assert('email', 'Lütfen geçerli bir e-posta giriniz.').isEmail();
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/account');
  }

  User.findById(req.user.id, (err, user) => {
    if (err) { return next(err); }
    user.email = req.body.email || '';
    user.profile.name = req.body.name || '';
    user.profile.gender = req.body.gender || '';
    user.profile.location = req.body.location || '';
    user.profile.website = req.body.website || '';
    user.save((err) => {
      if (err) {
        if (err.code === 11000) {
          req.flash('errors', { msg: 'Belirttiğiniz e-posta adresi başka bir kullanıcı tarafından kullanılmaktadır' });
          return res.redirect('/account');
        }
        return next(err);
      }
      req.flash('success', { msg: 'Profil bilgileri başarıyla güncellendi.' });
      res.redirect('/account');
    });
  });
};

/**
 * POST /account/password
 * Update current password.
 */
exports.updatePassword = (req, res, next) => {
  req.assert('password', 'Şifreniz en az 4 karakter uzunluğunda olmalıdır').len(4);
  req.assert('confirmPassword', 'Şifreler uyuşmamakta.').equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/account');
  }

  User.findById(req.user.id, (err, user) => {
    if (err) { return next(err); }
    user.password = req.body.password;
    user.save((err) => {
      if (err) { return next(err); }
      req.flash('success', { msg: 'Şifreniz değiştirildi.' });
      res.redirect('/account');
    });
  });
};

/**
 * POST /account/delete
 * Delete user account.
 */
exports.deleteAccount = (req, res, next) => {
  User.remove({ _id: req.user.id }, (err) => {
    if (err) { return next(err); }
    req.logout();
    req.flash('info', { msg: 'Hesabınız silindi.' });
    res.redirect('/');
  });
};

/**
 * GET /account/unlink/:provider
 * Unlink OAuth provider.
 */
exports.oauthUnlink = (req, res, next) => {
  const provider = req.params.provider;
  User.findById(req.user.id, (err, user) => {
    if (err) { return next(err); }
    user[provider] = undefined;
    user.tokens = user.tokens.filter(token => token.kind !== provider);
    user.save((err) => {
      if (err) { return next(err); }
      req.flash('info', { msg: `${provider} hesap bağı kaldırıldı.` });
      res.redirect('/account');
    });
  });
};

/**
 * GET /reset/:token
 * Reset Password page.
 */
exports.reset = (req, res, next) => {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  User
    .findOne({ passwordResetToken: req.params.token })
    .where('passwordResetExpires').gt(Date.now())
    .exec((err, user) => {
      if (err) { return next(err); }
      if (!user) {
        req.flash('errors', { msg: 'Şifre sıfırlama bağlantısı hatalı veya süresi dolmuş.' });
        return res.redirect('/forgot');
      }
      res.render('user/reset', {
        title: 'Şifre Sıfırla'
      });
    });
};

/**
 * POST /reset/:token
 * Process the reset password request.
 */
exports.doReset = (req, res, next) => {
  req.assert('password', 'Şifreniz en az 4 karakter uzunluğunda olmalıdır.').len(4);
  req.assert('confirm', 'Şifreler uyuşmuyor.').equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('back');
  }

  async.waterfall([
    function (done) {
      User
        .findOne({ passwordResetToken: req.params.token })
        .where('passwordResetExpires').gt(Date.now())
        .exec((err, user) => {
          if (err) { return next(err); }
          if (!user) {
            req.flash('errors', { msg: 'Şifre sıfırlama bağlantısı hatalı veya süresi dolmuş.' });
            return res.redirect('back');
          }
          user.password = req.body.password;
          user.passwordResetToken = undefined;
          user.passwordResetExpires = undefined;
          user.save((err) => {
            if (err) { return next(err); }
            req.logIn(user, (err) => {
              done(err, user);
            });
          });
        });
    },
    function (user, done) {
      const transporter = nodemailer.createTransport({
        service: 'SendGrid',
        auth: {
          user: process.env.SENDGRID_USER,
          pass: process.env.SENDGRID_PASSWORD
        }
      });
      const mailOptions = {
        to: user.email,
        from: 'no-reply@multiplayer2048.com',
        subject: 'Multiplayer2048 şifreniz değiştirildi',
        text: `Merhaba,\n\n ${user.email} e-posta adresiyle kayıt ettiğiniz hesabınızın şifresi az önce değiştirildi.\n`
      };
      transporter.sendMail(mailOptions, (err) => {
        req.flash('success', { msg: 'Başarılı! Şifreniz değiştirildi.' });
        done(err);
      });
    }
  ], (err) => {
    if (err) { return next(err); }
    res.redirect('/');
  });
};

/**
 * GET /forgot
 * Forgot Password page.
 */
exports.forgot = (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.render('user/forgot', {
    title: 'Şifremi Unuttum'
  });
};

/**
 * POST /forgot
 * Create a random token, then the send user an email with a reset link.
 */
exports.doForgot = (req, res, next) => {
  req.assert('email', 'Lütfen geçerli bir e-posta adresi giriniz.').isEmail();
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/forgot');
  }

  async.waterfall([
    function (done) {
      crypto.randomBytes(16, (err, buf) => {
        const token = buf.toString('hex');
        done(err, token);
      });
    },
    function (token, done) {
      User.findOne({ email: req.body.email }, (err, user) => {
        if (!user) {
          req.flash('errors', { msg: 'Belirttiğiniz e-posta adresi bulunamadı.' });
          return res.redirect('/forgot');
        }
        user.passwordResetToken = token;
        user.passwordResetExpires = Date.now() + 3600000; // 1 hour
        user.save((err) => {
          done(err, token, user);
        });
      });
    },
    function (token, user, done) {
      const transporter = nodemailer.createTransport({
        service: 'SendGrid',
        auth: {
          user: process.env.SENDGRID_USER,
          pass: process.env.SENDGRID_PASSWORD
        }
      });
      const mailOptions = {
        to: user.email,
        from: 'no-reply@multiplayer2048.com',
        subject: 'Multiplayer2048 hesabınızı sıfırlayın',
        text: `Bu e-postayı Multiplayer2048 oyunundaki hesabınızın şifresini sıfırlamak için aldınız.\n\n
          Şifrenizi sıfırlamak istiyorsanız aşağıdaki linki tarayıcınıza kopyalayın veya direk tıklayın:\n\n
          http://${req.headers.host}/reset/${token}\n\n
          Eğer bu isteği siz yapmadıysanız lütfen herhangi bir işlem yapmayınız.\n`
      };
      transporter.sendMail(mailOptions, (err) => {
        req.flash('info', { msg: `${user.email} e-posta adresine şifre sıfırlama bağlantısı gönderilmiştir.` });
        done(err);
      });
    }
  ], (err) => {
    if (err) { return next(err); }
    res.redirect('/forgot');
  });
};
