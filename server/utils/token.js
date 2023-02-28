const
  { sign } = require("jsonwebtoken"),
  { jwtSecret } = require("../config/keys.js");

module.exports = id => {
  const token = sign(
    { user: id },
    jwtSecret,
    { expiresIn: "365 days" }
  );

  return token;
}
