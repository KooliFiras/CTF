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
} from '../actions/actionTypes';

import { createReducer, createActions } from 'reduxsauce'


const initialState = {
    error: null,
    user: {},
    authorized: false,
};



const   Auth = (state = initialState, action) => {
    switch (action.type) {


        case SIGN_UP_SUCCESS:


            return {...state, authorized: true, user: action.user }


        case SIGN_IN_SUCCESS:

            return {...state, authorized: true, user: action.user }



        case SIGN_IN_ERROR:

            return {...state, error: action.error }


        case SIGN_UP_ERROR:
            return {...state, error: action.error }


        case SIGN_OUT_SUCCESS:
            return {...state, authorized: false,user:{} }


        case SET_USER_AUTHORIZED:
             return {...state, authorized: true }


        default:
            return state;
    }
};


export default Auth = Auth ;
