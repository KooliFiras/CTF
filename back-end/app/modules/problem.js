var mongoose = require ('mongoose')

var problemSchema = new mongoose.Schema({

    title:{type:String,
            required:true,
            unique:true
            },
    description: {type:String,unique:true},
    problem_statement: {type:String,unique:true},
    input_format: {type:String,unique:true},
    constraints: {type:String,unique:true},
    output_format: {type:String,unique:true},
    tags: {type:String,unique:true},
    language:{type:String},
    slug:{type:String},
    moderators:[{type:mongoose.Schema.Types.String,
                ref:'Participant'}],

    list_of_solutions:[{type:mongoose.Schema.Types.ObjectId}],
    solution: {type:String},
    categorie: {type:String},
    image: {type:String},
    score: {type:Number
            },
    creation_date:{type:Date},
    note:{type:Number},
    user_solved_it:[{type:mongoose.Schema.Types.ObjectId,
                    ref:'Participant'}],
    source_code:{type:String},
    list_ressources_associated:[{type:Object}],
    list_of_previous_tries:[{type:Object}],
    list_files_associated:[{type:Object}],
    specilized_skills:{type:String},
    programming_language:{type:String},
    challenge_difficulty: {type:String}

})

module.exports=mongoose.model('Problem',problemSchema)