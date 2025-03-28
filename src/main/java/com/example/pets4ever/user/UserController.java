package com.example.pets4ever.user;

import com.example.pets4ever.user.dtos.*;
import com.example.pets4ever.user.responses.*;
import com.example.pets4ever.utils.GetIdFromToken;
import com.example.pets4ever.utils.MyCookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;


@RestController
@RequestMapping("/api/v1/user")
public class UserController {

    @Autowired
    UserService userService;

    @Autowired
    GetIdFromToken getIdFromToken;

    @GetMapping("")
    public ResponseEntity<UserResponse> user(@RequestHeader("Authorization") String jwt) {

        String id = getIdFromToken.id(jwt);

        UserResponse user = userService.userById(id);
        return ResponseEntity.status(HttpStatus.OK).body(user);
    }
    @GetMapping("/{username}")
    public ResponseEntity<UserResponse> userByUsername(@PathVariable String username) {
        UserResponse user = userService.userByUsername(username);
        return ResponseEntity.status(HttpStatus.OK).body(user);
    }
    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        HttpHeaders headers = this.getHeadersWithExpiredCookies();
        return ResponseEntity.ok().headers(headers).body("Sessão encerrada");
    }
    @PostMapping
    public ResponseEntity<Object> signup(@RequestBody @Valid SignUpDTO data) {
        return ResponseEntity.ok(userService.create(data));
    }
    @PatchMapping("/email/{id}")
    public ResponseEntity<MessageResponse> email(@PathVariable String id, @RequestBody @Valid UpdateEmailDTO updateEmailDTO) {
        return ResponseEntity.status(HttpStatus.OK).body(userService.updateEmail(updateEmailDTO, id));
    }
    @PatchMapping("/profile/{id}")
    public ResponseEntity<List<FieldMessageResponse>> profile(@PathVariable String id, @RequestBody @Valid PatchProfileDTO patchProfileDTO) {
        return ResponseEntity.status(HttpStatus.OK).body(userService.patchProfile(id, patchProfileDTO));
    }
    @PatchMapping("/{id}/profile-img")
    public ResponseEntity<FieldMessageResponse> profileImg(@PathVariable String id, @ModelAttribute ProfileImgDTO profileImgDTO) throws IOException {
        System.out.println(profileImgDTO);
        return ResponseEntity.ok(userService.patchProfileImg(profileImgDTO, id));
    }
    @PatchMapping("/following")
    public ResponseEntity<MessageResponse> following(@RequestBody @Valid PatchFollowingDTO patchFollowingDTO){
        System.out.println(patchFollowingDTO);
        return ResponseEntity.status(HttpStatus.OK).body(userService.patchFollowing(patchFollowingDTO));
    }
    @PatchMapping("/{username}/password")
    public ResponseEntity<MessageResponse> password(@PathVariable String username, @RequestBody @Valid PatchPasswordDTO patchPasswordDTO) {
        return ResponseEntity.status(HttpStatus.OK).body(userService.patchPassword(username, patchPasswordDTO));
    }
    @PatchMapping("/forgotpassword")
    public ResponseEntity<MessageResponse> forgotPassword(@RequestBody @Valid ForgotPasswordDTO forgotPasswordDTO) {
        System.out.println(forgotPasswordDTO);
        return ResponseEntity.status(HttpStatus.OK).body(userService.forgotPassword(forgotPasswordDTO));
    }
    @DeleteMapping("/follower")
    public ResponseEntity<MessageResponse> follower(@RequestBody @Valid DeleteFollowerDTO deleteFollowerDTO) {
        return ResponseEntity.status(HttpStatus.OK).body(userService.deleteFollower(deleteFollowerDTO));
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<String> delete(@PathVariable String id){
        HttpHeaders headers = this.getHeadersWithExpiredCookies();
        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(userService.delete(id));
    }

    private HttpHeaders getHeadersWithExpiredCookies(){
        String jwt = null;
        MyCookie myCookie = new MyCookie();

        ResponseCookie jwtCookie = myCookie.generateCookie("jwt", jwt, 0, true, true);
        ResponseCookie hasSession = myCookie.generateCookie("hasSession", "yes", 0, false, false);

        HttpHeaders headers = new HttpHeaders();

        headers.add(HttpHeaders.SET_COOKIE, jwtCookie.toString());
        headers.add(HttpHeaders.SET_COOKIE, hasSession.toString());

        return headers;
    }
}






