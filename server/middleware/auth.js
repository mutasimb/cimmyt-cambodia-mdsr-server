const
  { verify } = require('jsonwebtoken'),
  { jwtSecret } = require("../config/keys.js");

module.exports = (req, res, next) => {
  const token = req.get("x-auth-token");
  if (!token || !token.startsWith("Bearer ")) return res.status(401).json({ message: 'No token' });

  try {
    verify(
      token.split(" ")[1],
      jwtSecret,
      (err, decoded) => {
        if (err) {
          return res.status(401).json({ message: 'Invalid token' });
        } else {
          req.idUser = decoded.user;
          next();
        }
      }
    );
  } catch (error) {
    return res.status(500).send({ message: error.message, error });
  }
};
