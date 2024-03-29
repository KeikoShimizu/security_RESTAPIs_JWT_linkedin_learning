import mongoose from "mongoose";

const Schema = mongoose.Schema;

export const userSchema = new Schema({
    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    hashPassword: {
        type:String,
        required: true
    },
    created_date: {
        type:Date,
        default: Date.now
    },
})

