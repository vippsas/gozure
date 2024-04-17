/*
Package notihub represents an http client
for microsoft azure notification hub
*/
package notihub

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"gopkg.in/xmlpath.v2"
)

const (
	apiVersionParam = "api-version"
	apiVersionValue = "2015-01"
	directParam     = "direct"

	// for connection string parsing
	schemeServiceBus  = "sb"
	schemeDefault     = "https"
	paramEndpoint     = "Endpoint="
	paramSaasKeyName  = "SharedAccessKeyName="
	paramSaasKeyValue = "SharedAccessKey="
)

const (
	Template           NotificationFormat = "template"
	AndroidFcmV1Format NotificationFormat = "FcmV1"
	AppleFormat        NotificationFormat = "apple"
	BaiduFormat        NotificationFormat = "baidu"
	KindleFormat       NotificationFormat = "adm"
	WindowsFormat      NotificationFormat = "windows"
	WindowsPhoneFormat NotificationFormat = "windowsphone"

	// Deprecated
	// Use AndroidFcmV1Format instead
	// https://learn.microsoft.com/en-us/azure/notification-hubs/notification-hubs-gcm-to-fcm
	AndroidFormat NotificationFormat = "gcm"

	AppleRegTemplate string = `<?xml version="1.0" encoding="utf-8"?>
<entry xmlns="http://www.w3.org/2005/Atom">
    <content type="application/xml">
        <AppleRegistrationDescription xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.microsoft.com/netservices/2010/10/servicebus/connect">
            <Tags>{{Tags}}</Tags>
            <DeviceToken>{{DeviceId}}</DeviceToken>
        </AppleRegistrationDescription>
    </content>
</entry>`
	AndroidRegTemplate string = `<?xml version="1.0" encoding="utf-8"?>
<entry xmlns="http://www.w3.org/2005/Atom">
    <content type="application/xml">
        <GcmRegistrationDescription xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.microsoft.com/netservices/2010/10/servicebus/connect">
            <Tags>{{Tags}}</Tags>
            <GcmRegistrationId>{{DeviceId}}</GcmRegistrationId>
        </GcmRegistrationDescription>
    </content>
</entry>`
)

type (
	Notification struct {
		Format  NotificationFormat
		Payload []byte
	}

	NotificationFormat string

	Registration struct {
		RegistrationId string             `json:"registrationId"`
		DeviceId       string             `json:"deviceId"`
		Service        NotificationFormat `json:"service"`
		Tags           string             `json:"tags"`
		ExpirationTime *time.Time         `json:"expirationTime,omitmepty"`
	}

	RegistrationRes struct {
		Id             string    `xml:"id"`
		Title          string    `xml:"title"`
		Updated        time.Time `xml:"updated"`
		RegistrationId string
		ETag           string
		ExpirationTime time.Time
	}

	NotificationHub struct {
		sasKeyValue    string
		sasKeyName     string
		hubURL         *url.URL
		client         HubClient
		expiryTimeFunc TimeFunc // use buildExpiryTimeFunc

		regIdPath *xmlpath.Path
		eTagPath  *xmlpath.Path
		expTmPath *xmlpath.Path
	}

	HubClient interface {
		Exec(req *http.Request) ([]byte, error)
	}

	TimeFunc func() time.Time

	hubHttpClient struct {
		httpClient *http.Client
	}
)

// UnixTimestamp calls f()
func (f TimeFunc) UnixTimestamp() string {
	unixTime := f().Unix()
	return strconv.FormatInt(unixTime, 10)
}

// Exec executes notification hub http request and handles the response
func (hc *hubHttpClient) Exec(req *http.Request) ([]byte, error) {
	return handleResponse(hc.httpClient.Do(req))
}

// GetContentType returns Content-Type
// associated with NotificationFormat
func (f NotificationFormat) GetContentType() string {
	switch f {
	case Template,
		AppleFormat,
		AndroidFormat,
		KindleFormat,
		BaiduFormat:
		return "application/json"
	}

	return "application/xml"
}

// IsValid identifies whether notification format is valid
func (f NotificationFormat) IsValid() bool {
	return f == Template ||
		f == AndroidFormat ||
		f == AppleFormat ||
		f == BaiduFormat ||
		f == KindleFormat ||
		f == WindowsFormat ||
		f == WindowsPhoneFormat ||
		f == AndroidFcmV1Format
}

// NewNotification initializes and returns Notification pointer
func NewNotification(format NotificationFormat, payload []byte) (*Notification, error) {
	if !format.IsValid() {
		return nil, fmt.Errorf("unknown format '%s'", format)
	}

	return &Notification{format, payload}, nil
}

// String returns Notification string representation
func (n *Notification) String() string {
	return fmt.Sprintf("&{%s %s}", n.Format, string(n.Payload))
}

// NewNotificationHub initializes and returns NotificationHub pointer
func NewNotificationHub(connectionString, hubPath string, client *http.Client) *NotificationHub {
	connData := strings.Split(connectionString, ";")

	hub := &NotificationHub{
		hubURL: &url.URL{},
	}

	for _, connItem := range connData {
		if strings.HasPrefix(connItem, paramEndpoint) {
			hubURL, err := url.Parse(connItem[len(paramEndpoint):])
			if err == nil {
				hub.hubURL = hubURL
			}
			continue
		}

		if strings.HasPrefix(connItem, paramSaasKeyName) {
			hub.sasKeyName = connItem[len(paramSaasKeyName):]
			continue
		}

		if strings.HasPrefix(connItem, paramSaasKeyValue) {
			hub.sasKeyValue = connItem[len(paramSaasKeyValue):]
			continue
		}
	}

	if hub.hubURL.Scheme == schemeServiceBus || hub.hubURL.Scheme == "" {
		hub.hubURL.Scheme = schemeDefault
	}

	hub.hubURL.Path = hubPath
	hub.hubURL.RawQuery = url.Values{apiVersionParam: {apiVersionValue}}.Encode()

	hub.client = &hubHttpClient{httpClient: client}
	hub.expiryTimeFunc = buildExpiryTimeFunc(time.Hour)

	hub.regIdPath = xmlpath.MustCompile("/entry/content/*/RegistrationId")
	hub.eTagPath = xmlpath.MustCompile("/entry/content/*/ETag")
	hub.expTmPath = xmlpath.MustCompile("/entry/content/*/ExpirationTime")

	return hub
}

// Send publishes notification to the azure hub
func (h *NotificationHub) Send(ctx context.Context, n *Notification, orTags []string) ([]byte, error) {
	b, err := h.send(ctx, n, orTags, nil)
	if err != nil {
		return nil, fmt.Errorf("NotificationHub.Send: %s", err)
	}

	return b, nil
}

func (h *NotificationHub) SendDirect(ctx context.Context, n *Notification, deviceHandle string) ([]byte, error) {
	b, err := h.sendDirect(ctx, n, deviceHandle)
	if err != nil {
		return nil, fmt.Errorf("NotificationHub.SendDirect: %s", err)
	}

	return b, nil
}

// Schedule publishes a scheduled notification to azure notification hub
func (h *NotificationHub) Schedule(ctx context.Context, n *Notification, orTags []string, deliverTime time.Time) ([]byte, error) {
	b, err := h.send(ctx, n, orTags, &deliverTime)
	if err != nil {
		return nil, fmt.Errorf("NotificationHub.Schedule: %s", err)
	}

	return b, nil
}

// send sends notification to the azure hub
func (h *NotificationHub) send(ctx context.Context, n *Notification, orTags []string, deliverTime *time.Time) ([]byte, error) {
	token := h.generateSasToken()
	buf := bytes.NewBuffer(n.Payload)

	headers := map[string]string{
		"Authorization":                 token,
		"Content-Type":                  n.Format.GetContentType(),
		"ServiceBusNotification-Format": string(n.Format),
		"X-Apns-Expiration":             h.expiryTimeFunc.UnixTimestamp(),
	}

	if len(orTags) > 0 {
		headers["ServiceBusNotification-Tags"] = strings.Join(orTags, " || ")
	}

	//IOS 13 and upwards require these headers to be set. They are not set by Notification Hub at the moment, so we need to send them
	if n.Format == AppleFormat {
		if isAppleBackgroundNotification(n.Payload) {
			headers["X-Apns-Push-Type"] = "background"
			headers["X-Apns-Priority"] = "5"
		} else {
			headers["X-Apns-Push-Type"] = "alert"
			headers["X-Apns-Priority"] = "10"
		}
	}

	url_ := &url.URL{
		Host:     h.hubURL.Host,
		Scheme:   h.hubURL.Scheme,
		Path:     h.hubURL.Path,
		RawQuery: h.hubURL.RawQuery,
	}

	if deliverTime != nil && deliverTime.Unix() > time.Now().Unix() {
		url_.Path = path.Join(url_.Path, "schedulednotifications")
		headers["ServiceBusNotification-ScheduleTime"] = deliverTime.Format("2006-01-02T15:04:05")
	} else {
		url_.Path = path.Join(url_.Path, "messages")
	}

	req, err := http.NewRequest("POST", url_.String(), buf)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	for header, val := range headers {
		req.Header.Set(header, val)
	}

	return h.client.Exec(req)
}

func (h *NotificationHub) sendDirect(ctx context.Context, n *Notification, deviceHandle string) ([]byte, error) {
	token := h.generateSasToken()
	buf := bytes.NewBuffer(n.Payload)

	headers := map[string]string{
		"Authorization":                       token,
		"Content-Type":                        n.Format.GetContentType(),
		"ServiceBusNotification-Format":       string(n.Format),
		"ServiceBusNotification-DeviceHandle": deviceHandle,
		"X-Apns-Expiration":                   h.expiryTimeFunc.UnixTimestamp(),
	}

	//IOS 13 and upwards require these headers to be set. They are not set by Notification Hub at the moment, so we need to send them
	if n.Format == AppleFormat {
		if isAppleBackgroundNotification(n.Payload) {
			headers["X-Apns-Push-Type"] = "background"
			headers["X-Apns-Priority"] = "5"
		} else {
			headers["X-Apns-Push-Type"] = "alert"
			headers["X-Apns-Priority"] = "10"
		}
	}

	query := h.hubURL.Query()
	query.Add(directParam, "")

	url_ := &url.URL{
		Host:     h.hubURL.Host,
		Scheme:   h.hubURL.Scheme,
		Path:     path.Join(h.hubURL.Path, "messages"),
		RawQuery: query.Encode(),
	}

	req, err := http.NewRequest("POST", url_.String(), buf)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	for header, val := range headers {
		req.Header.Set(header, val)
	}

	return h.client.Exec(req)
}

// generateSasToken generates and returns
// azure notification hub shared access signatue token
func (h *NotificationHub) generateSasToken() string {
	uri := &url.URL{
		Host:   h.hubURL.Host,
		Scheme: h.hubURL.Scheme,
	}
	targetUri := strings.ToLower(uri.String())

	expires := h.expiryTimeFunc.UnixTimestamp()
	toSign := fmt.Sprintf("%s\n%s", url.QueryEscape(targetUri), expires)

	mac := hmac.New(sha256.New, []byte(h.sasKeyValue))
	mac.Write([]byte(toSign))
	macb := mac.Sum(nil)

	signature := base64.StdEncoding.EncodeToString(macb)

	tokenParams := url.Values{
		"sr":  {targetUri},
		"sig": {signature},
		"se":  {expires},
		"skn": {h.sasKeyName},
	}

	return fmt.Sprintf("SharedAccessSignature %s", tokenParams.Encode())
}

func buildExpiryTimeFunc(delta time.Duration) TimeFunc {
	if delta <= 0 {
		panic("Attempted to build expiry TimeFunc with non-positive delta!")
	}
	return func() time.Time {
		return time.Now().Add(delta)
	}
}

// handleResponse reads http response body into byte slice
// if response contains an unexpected status code, error is returned
func handleResponse(resp *http.Response, inErr error) (b []byte, err error) {
	if inErr != nil {
		return nil, inErr
	}

	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = cerr
		}
	}()

	b, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if !isOKResponseCode(resp.StatusCode) {
		return nil, fmt.Errorf("got unexpected response status code: %d. response: %s", resp.StatusCode, b)
	}

	if len(b) == 0 {
		return []byte(fmt.Sprintf("response status: %s", resp.Status)), nil
	}

	return
}

// isOKResponseCode identifies whether provided
// response code matches the expected OK code
func isOKResponseCode(code int) bool {
	return code == http.StatusCreated || code == http.StatusOK
}

// Register sends registration to the azure hub
func (h *NotificationHub) Register(r Registration) (RegistrationRes, []byte, error) {
	regRes := RegistrationRes{}
	token := h.generateSasToken()

	headers := map[string]string{
		"Authorization": token,
		"Content-Type":  "application/atom+xml;type=entry;charset=utf-8",
	}

	payload := ""

	switch r.Service {
	case AppleFormat:
		payload = strings.Replace(AppleRegTemplate, "{{DeviceId}}", r.DeviceId, 1)
	case AndroidFormat:
		payload = strings.Replace(AndroidRegTemplate, "{{DeviceId}}", r.DeviceId, 1)
	default:
		return regRes, nil, errors.New("not implemented.")
	}
	payload = strings.Replace(payload, "{{Tags}}", r.Tags, 1)

	method := "POST"
	regURL := url.URL{
		Host:     h.hubURL.Host,
		Scheme:   h.hubURL.Scheme,
		Path:     path.Join(h.hubURL.Path, "registrations"),
		RawQuery: h.hubURL.RawQuery,
	}

	if r.RegistrationId != "" {
		method = "PUT"
		regURL.Path = path.Join(regURL.Path, r.RegistrationId)
	}

	urlStr := regURL.String()
	buf := bytes.NewBufferString(payload)
	req, err := http.NewRequest(method, urlStr, buf)
	if err != nil {
		return regRes, nil, err
	}

	for header, val := range headers {
		req.Header.Set(header, val)
	}

	res, err := h.client.Exec(req)
	if err == nil {
		if err = xml.Unmarshal(res, &regRes); err != nil {
			return regRes, res, err
		}
		rb := bytes.NewReader(res)
		if root, err := xmlpath.Parse(rb); err == nil {
			if regId, ok := h.regIdPath.String(root); ok {
				regRes.RegistrationId = regId
			} else {
				return regRes, res, errors.New("RegistrationId not fount")
			}
			if etag, ok := h.eTagPath.String(root); ok {
				regRes.ETag = etag
			} else {
				return regRes, res, errors.New("ETag not fount")
			}
			if expTm, ok := h.expTmPath.String(root); ok {
				if regRes.ExpirationTime, err = time.Parse("2006-01-02T15:04:05.999", expTm); err != nil {
					return regRes, res, err
				}
			} else {
				return regRes, res, err
			}
		} else {
			return regRes, res, errors.New("ExpirationTime not fount")
		}
	}
	return regRes, res, err
}

type iosBackgroundNotification struct {
	Aps aps `json:"aps"`
}
type aps struct {
	ContentAvailable int `json:"content-available"`
}

func isAppleBackgroundNotification(payload []byte) bool {
	var backgroundNot iosBackgroundNotification
	err := json.Unmarshal(payload, &backgroundNot)
	if err != nil {
		return false
	}

	return backgroundNot.Aps.ContentAvailable == 1
}
