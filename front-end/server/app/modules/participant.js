var mongoose = require ('mongoose')
var bcrypt = require('bcrypt-nodejs')

var participantSchema = new mongoose.Schema({

            username:{
                type:String,
                required:true
            },
            firstname: {
                type:String
            },
            lastname:{
                type:String
            },
            email:{
                type:String,
                unique:true,
                required:true
            },
            password:{
                type:String,
                required:true
            },
            avatar:{type:Object},

            github:{
            id: String,
            token: String,
            email: String,
            name: String
                },
        school:{
            type:String,
        },
        experience:{
            type:String,
        },
        country:{
        type:String,
        },
        score:{type:Number},
        problem_solved:[{type:mongoose.Schema.Types.ObjectId,
            ref:'Problem'}],
        problem_favorites:[{type:mongoose.Schema.Types.ObjectId,
            ref:'Problem'}],
        contests: [{type:mongoose.Schema.Types.ObjectId,
            ref:'Contest'}],
        notifications:[{type:mongoose.Schema.Types.ObjectId
        }],
        list_problems_added:[{type:mongoose.Schema.Types.ObjectId,
            ref:'Problem'}]


})


participantSchema.pre('save', function (next) {
    var user = this;
    if (this.isModified('password') || this.isNew) {
        bcrypt.genSalt(10, function (err, salt) {
            if (err) {
                return next(err);
            }
            bcrypt.hash(user.password, salt, null, function (err, hash) {
                if (err) {
                    return next(err);
                }
                user.password = hash;
                next();
            });
        });
    } else {
        return next();
    }
});

participantSchema.methods.comparePassword = function (passw, cb) {
    bcrypt.compare(passw, this.password, function (err, isMatch) {
        if (err) {
            return cb(err);
        }
        cb(null, isMatch);
    });
};



module.exports=mongoose.model('Participant',participantSchema)