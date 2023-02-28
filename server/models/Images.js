const
  { Schema, model } = require("mongoose"),

  ImageSchema = new Schema({
    name: { type: String },
    desc: { type: String },
    img: {
      data: { type: Buffer },
      contentType: { type: String }
    }
  });

module.exports = model("images", ImageSchema);
