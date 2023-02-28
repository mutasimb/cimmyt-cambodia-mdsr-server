const {
  DB_HOST,
  DB_NAME,
  DB_USER,
  DB_PASSWORD,
  JWT_SECRET
} = process.env;

module.exports = {
  mongoURI: `mongodb+srv://${ DB_USER }:${ DB_PASSWORD }@${ DB_HOST }/${ DB_NAME }?retryWrites=true&w=majority`,
  jwtSecret: JWT_SECRET
}
