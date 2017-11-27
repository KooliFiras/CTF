
var Alert = require('react-bootstrap').Alert;
import {
    INIT_AUTH,
    SIGN_UP_SUCCESS,
    SIGN_UP_ERROR,
    SIGN_IN_ERROR,
    SIGN_IN_SUCCESS,
    SIGN_OUT_SUCCESS,
    SET_FIRST_NAME,
    SET_LAST_NAME,
    SET_EMAIL,
    SET_PASSWORD,
    SET_CITY,
    SET_PHONE,
    SET_USER_AVATAR,
    SET_USER_AUTHORIZED,
    SET_USER_TYPE
} from './actionTypes';




//****prepare our actions *************//




//***********function to signup***************//
export const Signup = (newUser) => {

}


//***************function to sign-in****************//
export const SignIn = (user) => {

}

//**********Action to check if email used Before *********//

export const  checkEmail =(email) =>{

}


//*************Action to handle Error***************//
export const signInError = (error) => {

    return {
        type: SIGN_IN_ERROR,
        error: error
    }
}


//***********Action to handle Success *******************//
export const signInSuccess = (result) => {

    return {
        type: SIGN_IN_SUCCESS,
        user: result
    }
}



export const signUpSuccess = (result) => {

    return {
        type: SIGN_UP_SUCCESS,
        user: result
    }
}


//***************Action to hanlde Signout ***************//
export const signOut = () => {
    return dispatch => {}

}


//************Action signOutSuccess************//

export const signOutSuccess = () => {
    return {
        type: SIGN_OUT_SUCCESS
    }

};
