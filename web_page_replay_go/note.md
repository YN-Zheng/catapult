_This is a conclusion of the meeting in 22/2/2021_

## Replay
### Empty body
It seems that the image's and font's body are lost in the har files from HttpArchive. It's ok as long as the **browser accepts them**.

### 404 not found
There is `[TODO] %` 404 response during replay for different reasons:  
1. Request URL includes a timestamp 
2. User-dependent request. (e.g. browser)
3. Tracker (e.g. facebook's random URL) I don't remember details @gunesacar 


[WprGo Use a timestamp generated during recording in deterministic.js](https://github.com/catapult-project/catapult/commit/677b02eacd6fe0d32040649858b5248d7dc402da#diff-17a7db3419930889a93a2277b2adc938e7661a2757e5e817629f3ec7331b21d7)
### Browser configuration: firefox profile
1. Create a profile: 
    ```bash
    firefox -P
    ```
2. - [ ] [Load profile in OpenWPM](https://github.com/mozilla/OpenWPM/blob/master/docs/Configuration.md#load-a-profile)


## Conversion
### Double quoted Cookie
As discussed in this [issue](https://github.com/golang/go/issues/10195), "double-quoted" Cookie is not allowed in Golang.

This issue concerns us when we need to generate http.Request in Golang with cookies that are double-quoted in the har file. The conclusion is:
1. In principle, we should keep those cookies without any modification. Since it was accepted by the browser at the time the har file was exported.
2. The `http.Addcookie` method refuses them. We shall not change the source code for a very clear reason. 

- [ ] The possible way is to fork and use our own version of `http.Addcookie`.





### USER-AGENT
- RECORDING

user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.23 Safari/537.36

- REPLAYING

Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.23 Safari/537.36

