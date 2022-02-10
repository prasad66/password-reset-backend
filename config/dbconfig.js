const mongoose = require("mongoose");
const schema = mongoose.Schema;

const dbConnect = async () => {
    try {
        await mongoose.connect(
            process.env.DB_URL,
            {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                autoIndex: true,
            }
        );
        console.log("DB Connected");
    } catch (e) {
        console.log(e.message, "error in connecting db");
    }
};
const userSchema = schema({
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    verifyString: {
        type: String,
    },
});

const user = mongoose.model("user", userSchema, "user");

module.exports = { dbConnect, user };
