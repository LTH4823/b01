package org.zerock.b01.security.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@ToString
public class MemberSecurityDTO extends User implements OAuth2User {
    //일반적인 DTO와 다르게 시큐리티에서 쓸 DTO라서 내용이 다르다
    private String mid;

    private String mpw;

    private String email;

    private boolean del;

    private boolean social;

    private Map<String, Object> props; //소셜로그인 정보

    public MemberSecurityDTO(String email,String mpw, Map<String,Object> props){

        super(email,mpw, List.of(new SimpleGrantedAuthority("ROLE_USER")));

        this.mid = email;
        this.mpw = mpw;
        this.props = props;
        //db를 안쓰면 이거면 됨

    }


    public MemberSecurityDTO(String username, String password, String email,
                             boolean del, boolean social,
                             Collection<? extends GrantedAuthority> authorities) {

        super(username, password, authorities);

        this.mid = username;
        this.mpw = password;
        this.email = email;
        this.del = del;
        this.social = social;

    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.props;
    }

    @Override
    public String getName() {
        return this.mid;
    }
}