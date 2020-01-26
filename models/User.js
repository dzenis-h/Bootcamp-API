const crypto = require("crypto");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "Please add a name"]
  },
  email: {
    type: String,
    required: [true, "Please add an email"],
    unique: true,
    match: [
      /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
      "Please add a valid email"
    ]
  },
  role: {
    type: String,
    enum: ["user", "publisher"],
    default: "user"
  },
  password: {
    type: String,
    required: [true, "Please add a password"],
    minlength: 6,
    select: false // don't select the password, cause we don't want that to be send to the FE
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Encrypt password using bcrypt
UserSchema.pre("save", async function(next) {
  if (!this.isModified("password")) {
    next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Sign JWT and return
UserSchema.methods.getSignedJwtToken = function() {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE
  });
};

// Match user entered password to hashed password in database
UserSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Generate and hash password token
UserSchema.methods.getResetPasswordToken = function() {
  // Generate token
  // NOTE: We'll include this into the URL send to the user, so that's why we're returning this value from this method
  const resetToken = crypto.randomBytes(20).toString("hex"); // look at this as 'salt' :)

  // NOTE: However, we'll store the hashed version to DB. The logic here is, the user will receive an email
  // containing the 'resetToken' and we'll extract that token from params and run it again through the same
  // Crypto function, in our controller method. After that, we'll search for a user in our DB that matches
  // the 'resetPasswordToken' field that was set using the method above.

  this.resetPasswordToken = crypto
    // Hash token and set to resetPasswordToken field
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // Set the expire field
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 min

  return resetToken;
};

module.exports = mongoose.model("User", UserSchema);
