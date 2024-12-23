import mongoose from "mongoose";

const lessonSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
    },
    content: {
        type: String,
        required: true,
    },
    materials: [{
        url: {
            type: String,
            required: true,
        },
        type: {
            type: String,
            enum: ['image', 'pdf', 'video', 'document', 'other'],
            required: true,
        },
    }],
    course: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Course',
        required: true,
    }
}, { timestamps: true });

module.exports = mongoose.model('Lesson', lessonSchema);
