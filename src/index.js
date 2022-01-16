import * as SecureStore from 'expo-secure-store';

class IDaaSModule{
    apiVersion = 'v1';
    isRefreshing = false;

    localStoragePrefix = 'idaas-';
    deauthHandler = function(){};

    constructor(domain){
        this.domain = domain;      
    }

    async init(){
        return new Promise((resolve, reject) => {
            let { 
                refreshToken, 
                refreshTokenExpiry, 
                accessToken, 
                accessTokenExpiry
            } = await this.retrieveSecureStoreObject() || {};

            this.refreshToken = refreshToken;
            this.refreshTokenExpiry = refreshTokenExpiry || 0;
    
            this.accessToken = accessToken;
            this.accessTokenExpiry = accessTokenExpiry || 0;    

            resolve(true);
        });
    }

    async isAuthenticated(){
        // check for a valid refresh token
        if ( !this.refreshToken || 
            this._timestamp_() > this.refreshTokenExpiry ){
            return false;
        }

        // check for a valid refresh token
        if ( this.accessToken && 
            this.accessTokenExpiry > this._timestamp_() ){
            return true;   
        }

        // try to obtain a new access token
        if ( !await this.newAccessToken() ){
            return false;
        }

        return true;
    }

    async auth({ email, username, password }){
        return new Promise((resolve, reject) => {
            axios.post(this.uri('auth'), {
                email, username, password
            }).then(({data , status}) => {
                if ( status !== 200 ){
                    return resolve(false);
                }
                
                let { 
                    refreshToken, 
                    accessToken, 
                    refreshTokenExpiry, 
                    accessTokenExpiry,
                    user
                } = data.data;
                
                if ( !refreshToken ){
                    return false;
                }
                
                await this.updateSecureStoreObject({
                    refreshToken,
                    accessToken,
                    accessTokenExpiry,
                    refreshTokenExpiry,
                    user
                });

                this.refreshToken = refreshToken;
                this.refreshTokenExpiry = refreshTokenExpiry;
                this.accessTokenExpiry = accessTokenExpiry;
                this.accessToken = accessToken;

                resolve(true);
            }).catch(err => {
                resolve(false);
            });
        });
    }

    /**
     * O
     * @param {*} captcha 
     * @param {*} param1 
     * @returns 
     */
    async sso(captcha, { email, phone }){
        return new Promise(async (resolve, reject) => {
            if ( !this.captchaToken ){
                return resolve(false);
            }

            axios.get(this.uri('sso'), {
                headers: {
                    'x-captcha-token': this.captchaToken,
                    'x-captcha-code': captcha
                },
                query: { email, phone }
            }).then(({ data, status }) => {
                /**
                 * 404 - invalid email
                 * 401 - invalid captcha attempt
                 * 429 - too many sso requests
                 */
                resolve(status);
            }).catch(err => {
                resolve(false);
            })
        });
    }
    
    /**
     * Invalidates refresh token so that no more access tokens
     * can be requested with it. Refresh tokens may still remain
     * valid and a webhook can be attached on the IDaaS platform
     * to deal with that.
     * @returns {boolean}
     */
    async deauth(){
        return new Promise(async (resolve, reject) => {
            if ( !this.refreshToken ){
                return resolve(false);
            }

            await this.updateSecureStoreObject({
                refreshToken: undefined,
                accessToken: undefined,
                refreshTokenExpiry: undefined,
                accessTokenExpiry: undefined,
                userData: undefined
            });

            axios.delete(this.uri('auth'), {
                headers:{
                    'x-refresh-token': this.refreshToken
                }
            }).then(res => {
                resolve(true);
            }).catch(err => {
                resolve(false);
            });

            this.refreshToken = null;
            this.accessToken = null;
        });
    }
    
    /**
     * 
     * @param {boolean} force - force a new access token 
     * even if current one is still valid 
     * @returns {boolean} - true | false
     */
    async newAccessToken(force = false){
        return new Promise(async (resolve, reject) => {
            if ( !this.refreshToken ){
                this.deauthHandler(false);
                return resolve(false);
            }

            if ( this.isRefreshing ){
                let intervalId = setInterval(() => {
                    if ( !this.isRefreshing ){
                        clearInterval(intervalId);
                        resolve(true);
                    }
                }, 500);
                return;
            }

            if ( this.accessTokenExpiry > this._timestamp_() && !force ){
                return resolve(true);
            }

            this.isRefreshing = true;

            await axios.get(this.uri('auth'), {headers:{
                'x-refresh-token': this.refreshToken
            }}).then(({data, status}) => {
                let { accessToken, expiry, user } = data.data;
                
                if ( !accessToken ){
                    resolve(false);
                    return this.deauthHandler({ status });
                }
                
                await this.updateSecureStoreObject({
                    accessToken,
                    user,
                    accessTokenExpiry: expiry
                });

                this.accessToken = accessToken;
                this.accessTokenExpiry = expiry;

                resolve(data.data);
            }).catch(err => {
                resolve(false);
                return this.deauthHandler({ status: 500 })
            })

            this.isRefreshing = false;
        });
    }

    async obtainCaptcha(){
        return new Promise(async (resolve, reject) => {
            await axios.get(this.uri('captcha'))
            .then(({ data }) => {
                resolve(data.data);
            }).catch(err => {
                resolve(err);
            });
        });
    }

    /**
     * 
     * @param {function} handler 
     * @returns 
     */
    async request(handler){
        if ( this._timestamp_() > this.refreshTokenExpiry ){
            return this.deauthHandler();
        }

        if ( this._timestamp_() > this.accessTokenExpiry ){
            await this.newAccessToken()
        }

        handler(this.accessToken);
    }

    setDeauthHandler(handler){
        this.deauthHandler = handler;
    }

    async getUser(){
        if ( !this.isAuthenticated() ){
            return false;
        }

        return new Promise(async (resolve, reject) => {
            try{
                let user = JSON.parse(
                    this.getLocalStorageItem('user-data') || '{}'
                );

                if ( user.user_id ){
                    return resolve(user);
                }
            }catch(e){
                // move ahead
            }

            await axios.get(this.uri('user'), {
                headers:{
                    'x-access-token':this.accessToken
                }
            }).then(({data, status}) => {
                if ( status != 200 ){
                    return resolve(false);
                }

                await this.updateSecureStoreObject({
                    user: data.data
                });

                resolve(data.data);
            }).catch(err => {
                resolve(false);
            });
        });
    }

    _timestamp_(){
        return Math.floor(Date.now() / 1000);
    }

    uri(e){
        return `https://${this.domain}/${this.apiVersion}/${e}`
    }
    
    /* LOCAL STORAGE WARPPERS FOR PREFIXING */
    async updateSecureStoreObject(props){
        return new Promise((resolve, reject) => {

        });
    }

    async retrieveSecureStoreObject(){
        return new Promise((resolve, reject) => {

        });
    }
}

export default IDaaSModule;