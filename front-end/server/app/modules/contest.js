var mongoose = require ('mongoose')

var contestSchema = new mongoose.Schema({

    title:{type:String,
        required:true,
        unique:true
        },
    description: {type:String},
    moderators:[
                {type:mongoose.Schema.Types.String,
                ref:'Participant'}
                ],
    creation_date:{type:Date},
    start_date:{type:Date,
                required:true
                },
    end_date:{type:Date,
            required:true
              },
    list_of_problems:[
        {
            title:{type:mongoose.Schema.Types.String,
                ref:'Problem'},
            score: {type:Number, default:0}
        }
                    ],

    list_participant:[{type:mongoose.Schema.Types.String,
                        ref:'Participant'}],
    organization_type:{
        type:String,
        required:true
    },
    organization_name:{
        type:String,
        required:true
    },
    tagline:{type:String},
    prizes:{type:String},
    rules:{type:String},
    scoring:{type:String},

})

module.exports=mongoose.model('Contest',contestSchema)