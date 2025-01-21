package com.Grook.App;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = {
		"spring.security.oauth2.client.registration.azure.client-id=test-client-id",
		"spring.security.oauth2.client.registration.azure.client-secret=test-client-secret"
})
class AppApplicationTests {

	@Test
	void contextLoads() {
	}

}
