package access

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"ferry-srv/log"
	"ferry-srv/utils"

	"github.com/samber/mo"

	"github.com/patrickmn/go-cache"
)

type argonAccountData struct {
	AccountID int    `json:"account_id"`
	UserID    int    `json:"user_id"`
	Username  string `json:"username"`
}

type argonResponse struct {
	Valid       bool              `json:"valid"`
	ValidWeak   bool              `json:"valid_weak,omitempty"`
	Username    string            `json:"username,omitempty"`
	Cause       string            `json:"cause"`
	AccountData *argonAccountData `json:"account_data"`
}

// i dont wanna spam the server lowkey...
var (
	argonCache = cache.New(3*time.Minute, 5*time.Minute)
	invalids   = cache.New(2*time.Minute, 3*time.Minute)

	rlToken string
)

func getToken() (string, error) {
	if rlToken == "" {
		return "", fmt.Errorf("env for argon ratelimit token is not defined!")
	} else {
		return rlToken, nil
	}
}

func argonUrl(ver uint8, endpoint string) string {
	var base string

	switch ver {
	default:
	case 1:
		base = "https://argon.globed.dev/v1"
	case 2:
		base = "https://argon.globed.dev/v2"
	}

	return fmt.Sprintf("%s%s", base, endpoint)
}

func newArgonRequest(user *utils.ArgonUser, strong bool, ver uint8) (*http.Request, error) {
	method := http.MethodGet
	endpoint := ""
	var body io.Reader

	switch ver {
	case 1:
		if strong {
			endpoint = "/validation/check-strong"
		} else {
			endpoint = "/validation/check"
		}
	case 2:
		method = http.MethodPost
		endpoint = "/token/validate"
		payload, err := json.Marshal(struct {
			Token string `json:"token"`
		}{Token: user.Token})
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(payload)
	default:
		return nil, fmt.Errorf("unsupported Argon API version %d", ver)
	}

	u, err := url.Parse(argonUrl(ver, endpoint))
	if err != nil {
		return nil, err
	}
	if ver == 1 {
		q := u.Query()
		q.Set("account_id", fmt.Sprintf("%v", user.Account))
		q.Set("authtoken", user.Token)
		if strong {
			q.Set("user_id", fmt.Sprintf("%v", user.User))
			q.Set("username", user.Username)
		}
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if ver == 2 {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func ValidateArgonUser(user *utils.ArgonUser, strong bool, ver uint8) mo.Result[utils.ArgonUser] {
	if ver != 1 && ver != 2 {
		return mo.Errf[utils.ArgonUser]("unsupported Argon API version %d", ver)
	}

	tokenHash := sha256.Sum256([]byte(user.Token))
	tokenKey := fmt.Sprintf("%x", tokenHash)
	cacheKey := fmt.Sprintf("%d:%d:%s", ver, user.Account, tokenKey)
	if ver == 1 {
		if strong {
			cacheKey += fmt.Sprintf(":strong:%d:%s", user.User, user.Username)
		} else {
			cacheKey += ":weak"
		}
	}
	invalidKey := fmt.Sprintf("%d:%s", ver, tokenKey)
	if _, found := invalids.Get(invalidKey); found {
		return mo.Errf[utils.ArgonUser]("Argon token is invalid")
	}

	if u, found := argonCache.Get(cacheKey); found {
		return mo.Ok(u.(utils.ArgonUser))
	}

	req, err := newArgonRequest(user, strong, ver)
	if err != nil {
		return mo.Err[utils.ArgonUser](err)
	}

	req.Header.Set("User-Agent", "ModComments/1.0")

	argon, err := getToken()
	if err != nil {
		log.Warn("Failed to get Argon API ratelimit token: %s", err.Error())
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", argon))
	}

	log.Trace("Sending Argon v%d %s request for account of ID %v", ver, req.Method, user.Account)
	client := &http.Client{Timeout: 15 * time.Second}

	resp, reqErr := client.Do(req)
	if reqErr != nil {
		return mo.Err[utils.ArgonUser](reqErr)
	}
	defer resp.Body.Close()

	log.Trace("Argon status code received: %v, for account of ID %v", resp.StatusCode, user.Account)

	if resp.StatusCode != http.StatusOK {
		return mo.Errf[utils.ArgonUser]("argon server returned status code %v", resp.StatusCode)
	}

	var valid argonResponse
	if err := json.NewDecoder(resp.Body).Decode(&valid); err != nil {
		return mo.Errf[utils.ArgonUser]("failed to parse argon response: %v", err)
	} else {
		log.Trace("Argon status of account of ID %v retrieved", user.Account)
	}

	if valid.Valid {
		if ver == 2 {
			if valid.AccountData == nil {
				return mo.Errf[utils.ArgonUser]("argon v2 response is missing account data")
			}
			if valid.AccountData.AccountID != user.Account {
				return mo.Errf[utils.ArgonUser](
					"argon v2 account ID %d does not match requested account ID %d",
					valid.AccountData.AccountID,
					user.Account,
				)
			}
			user.User = valid.AccountData.UserID
			user.Username = valid.AccountData.Username
		}

		log.Info("Argon status of account of ID %v is valid", user.Account)
		user.Token = ""

		argonCache.Set(cacheKey, *user, cache.DefaultExpiration)
		return mo.Ok(*user)
	}

	invalids.Set(invalidKey, true, cache.DefaultExpiration)
	if valid.Cause == "" {
		return mo.Errf[utils.ArgonUser]("Argon token is invalid")
	}
	return mo.Errf[utils.ArgonUser]("cause: %s", valid.Cause)
}

func init() {
	rlToken = os.Getenv("ARGON")
}
