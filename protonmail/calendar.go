package protonmail

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/emersion/go-ical"
	"io"
	"log"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const calendarPath = "/calendar/v1"

type CalendarFlags int

type Calendar struct {
	ID         string
	Type       int
	CreateTime Timestamp
	Members    []CalendarMemberView
}

type CalendarBootstrap struct {
	Keys       []CalendarKey
	Passphrase CalendarPassphrase
	Members    []CalendarMemberView
	// ... CalendarSettings
}

type CalendarKey struct {
	ID           string
	PrivateKey   string
	PassphraseID string
	Flags        int
	CalendarID   string
}

type CalendarPassphrase struct {
	Flags             int
	ID                string
	MemberPassphrases []CalendarMemberPassphrase
	CalendarID        string
}

type CalendarMemberView struct {
	ID          string
	Permissions int
	Email       string
	AddressID   string
	CalendarID  string
	Name        string
	Description string
	Color       string
	Display     int
	Priority    int
	Flags       int
}

type CalendarMemberPassphrase struct {
	MemberID   string
	Passphrase string
	Signature  string
}

type CalendarEventPermissions int

const (
	CalendarEventAvailability CalendarEventPermissions = 1 << iota
	CalendarEventRead
	CalendarEventReadMemberList
	CalendarEventWrite
	CalendarEventAdmin
	CalendarEventOwner
)

type CalendarEvent struct {
	ID                         string
	CalendarID                 string
	SharedEventID              string
	CalendarKeyPacket          string
	CreateTime, ModifyTime     Timestamp
	LastEditTime               Timestamp
	StartTime, EndTime         Timestamp
	StartTimezone, EndTimezone string
	FullDay                    int
	UID                        string
	IsOrganizer                int
	RecurrenceID               string
	Exdates                    []interface{}
	RRule                      interface{}
	Author                     string
	Permissions                CalendarEventPermissions
	SharedKeyPacket            string
	SharedEvents               []CalendarEventCard
	CalendarEvents             []CalendarEventCard
	PersonalEvents             []CalendarEventCard
	AttendeesEvents            []CalendarEventCard
	Attendees                  []interface{}
}

type CalendarEventCardType int

const (
	CalendarEventCardClear CalendarEventCardType = iota
	CalendarEventCardEncrypted
	CalendarEventCardSigned
	CalendarEventCardEncryptedAndSigned
)

func (t CalendarEventCardType) Signed() bool {
	switch t {
	case CalendarEventCardSigned, CalendarEventCardEncryptedAndSigned:
		return true
	default:
		return false
	}
}

func (t CalendarEventCardType) Encrypted() bool {
	switch t {
	case CalendarEventCardEncryptedAndSigned:
		return true
	default:
		return false
	}
}

type CalendarEventCard struct {
	Type      CalendarEventCardType
	Data      string
	Signature string
	MemberID  string `json:",omitempty"`
	Author    string `json:",omitempty"`
}

func FindMemberViewFromKeyring(members []CalendarMemberView, kr openpgp.KeyRing) (*CalendarMemberView, error) {
	for _, _member := range members {
		for _, userKey := range kr.DecryptionKeys() {
			for _, identity := range userKey.Entity.Identities {
				if _member.Email == identity.UserId.Email {
					return &_member, nil
				}
			}
		}
	}
	return nil, errors.New("could not find a CalendarMemberView for keyring")
}

func (bootstrap *CalendarBootstrap) DecryptKeyring(userKr openpgp.KeyRing) (openpgp.KeyRing, error) {
	var calKr openpgp.EntityList
	for _, key := range bootstrap.Keys {
		var passphrase *CalendarMemberPassphrase

		member, err := FindMemberViewFromKeyring(bootstrap.Members, userKr)
		if err != nil {
			return nil, err
		}

		for _, _passphrase := range bootstrap.Passphrase.MemberPassphrases {
			if _passphrase.MemberID == member.ID {
				passphrase = &_passphrase
				break
			}
		}
		if passphrase == nil {
			return nil, errors.New("could not find a MemberPassphrase for MemberID")
		}

		passphraseEnc, err := armor.Decode(strings.NewReader(passphrase.Passphrase))
		if err != nil {
			return nil, err
		}

		md, err := openpgp.ReadMessage(passphraseEnc.Body, userKr, nil, nil)
		if err != nil {
			return nil, err
		}

		passphraseBytes, err := io.ReadAll(md.UnverifiedBody)
		if err != nil {
			return nil, err
		}

		/*		signatureData, err := armor.Decode(strings.NewReader(passphrase.Signature))
				if err != nil {
					return nil, err
				}
				_, err = openpgp.CheckArmoredDetachedSignature(userKr, bytes.NewReader(passphraseBytes), signatureData.Body, nil)
				if err != nil {
					return nil, err
				}*/

		keyKr, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key.PrivateKey))
		if err != nil {
			return nil, err
		}

		for _, calKey := range keyKr {
			err = calKey.PrivateKey.Decrypt(passphraseBytes)
			if err != nil {
				return nil, err
			}

			for _, subKey := range calKey.Subkeys {
				err := subKey.PrivateKey.Decrypt(passphraseBytes)
				if err != nil {
					return nil, err
				}
			}
		}

		calKr = append(calKr, keyKr...)
	}
	return calKr, nil
}

func (card *CalendarEventCard) Read(userKr openpgp.KeyRing, calKr openpgp.KeyRing, keyPacket string) (*openpgp.MessageDetails, error) {
	if !card.Type.Encrypted() {
		md := &openpgp.MessageDetails{
			IsEncrypted:    false,
			IsSigned:       false,
			UnverifiedBody: strings.NewReader(card.Data),
		}

		if !card.Type.Signed() {
			return md, nil
		}

		signed := strings.NewReader(card.Data)
		signature := strings.NewReader(card.Signature)
		signer, err := openpgp.CheckArmoredDetachedSignature(userKr, signed, signature, nil)
		md.IsSigned = true
		md.SignatureError = err
		if signer != nil {
			md.SignedByKeyId = signer.PrimaryKey.KeyId
			md.SignedBy = entityPrimaryKey(signer)
		}
		return md, nil
	}

	keyPacketData := base64.NewDecoder(base64.StdEncoding, strings.NewReader(keyPacket))
	ciphertext := base64.NewDecoder(base64.StdEncoding, strings.NewReader(card.Data))
	msg := io.MultiReader(keyPacketData, ciphertext)
	md, err := openpgp.ReadMessage(msg, calKr, nil, nil)
	if err != nil {
		return nil, err
	}

	if card.Type.Signed() {
		r := &detachedSignatureReader{
			md:        md,
			signature: strings.NewReader(card.Signature),
			keyring:   userKr,
		}
		r.body = io.TeeReader(md.UnverifiedBody, &r.signed)

		md.UnverifiedBody = r
	}

	return md, nil
}

func (c *Client) ListCalendars() ([]*Calendar, error) {
	req, err := c.newRequest(http.MethodGet, calendarPath, nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Calendars []*Calendar
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Calendars, nil
}

func (c *Client) BootstrapCalendar(id string) (*CalendarBootstrap, error) {
	req, err := c.newRequest(http.MethodGet, calendarPath+"/"+id+"/bootstrap", nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		*CalendarBootstrap
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.CalendarBootstrap, nil
}

type CalendarEventFilter struct {
	Start, End     Timestamp
	Timezone       string
	Page, PageSize int
}

func (c *Client) ListCalendarEvents(calendarID string, filter *CalendarEventFilter) ([]*CalendarEvent, error) {
	v := url.Values{}

	if filter != nil {
		v.Set("Start", strconv.FormatInt(int64(filter.Start), 10))
		v.Set("End", strconv.FormatInt(int64(filter.End), 10))
		v.Set("Timezone", filter.Timezone)
		v.Set("Page", strconv.Itoa(filter.Page))
		if filter.PageSize > 0 {
			v.Set("PageSize", strconv.Itoa(filter.PageSize))
		}
	}

	req, err := c.newRequest(http.MethodGet, calendarPath+"/"+calendarID+"/events?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Events []*CalendarEvent
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Events, nil
}

func (c *Client) GetCalendarEvent(calendarID string, eventID string) (*CalendarEvent, error) {
	req, err := c.newRequest(http.MethodGet, calendarPath+"/"+calendarID+"/events/"+eventID, nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Event *CalendarEvent
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Event, nil
}

func concat(slices [][]string) []string {
	var totalLen int
	for _, s := range slices {
		totalLen += len(s)
	}
	tmp := make([]string, totalLen)
	var i int
	for _, s := range slices {
		i += copy(tmp[i:], s)
	}
	return tmp
}

type CalendarEventCreateOrUpdateData struct {
	Color                *string
	CalendarKeyPacket    string              `json:",omitempty"`
	CalendarEventContent []CalendarEventCard `json:",omitempty"`
	SharedKeyPacket      string              `json:",omitempty"`
	SharedEventContent   []CalendarEventCard `json:",omitempty"`
	Permissions          int                 `json:",omitempty"`
	IsOrganizer          int                 `json:",omitempty"`
	// Notifications, AttendeesEventContent, AddedProtonAttendees, Attendees, CancelledOccurrenceContent, IsPersonalSingleEdit, RemovedAttendeeAddresses ...
}

type CalendarEventSyncReq struct {
	MemberID string
	Events   []interface{}
}

type CalendarEventCreateSyncEntry struct {
	Overwrite int
	Event     *CalendarEventCreateOrUpdateData
}

type CalendarEventUpdateSyncEntry struct {
	ID    string
	Event *CalendarEventCreateOrUpdateData
}

var sharedSignedFields = []string{
	"uid",
	"dtstamp",
	"dtstart",
	"dtend",
	"recurrence-id",
	"rrule",
	"exdate",
	"organizer",
	"sequence",
}
var sharedEncryptedFields = []string{
	"uid",
	"dtstamp",
	"created",
	"description",
	"summary",
	"location",
}

var calendarSignedFields = []string{
	"uid",
	"dtstamp",
	"exdate",
	"status",
	"transp",
}
var calendarEncryptedFields = []string{
	"uid",
	"dtstamp",
	"comment",
}

/*var personalSignedFields = []string{
	"uid",
	"dtstamp",
}
var personalEncryptedFields = []string{}*/

var usedFields = concat([][]string{
	sharedSignedFields,
	sharedEncryptedFields,

	calendarSignedFields,
	calendarEncryptedFields,
	/*
		personalSignedFields,
		personalEncryptedFields,*/
})

// ... attendeesSigned/EncryptedFields
func pickProps(event *ical.Event, propNames []string) *ical.Component {
	evt := ical.NewEvent()
	for _, propName := range propNames {
		props := event.Props.Values(propName)
		if props != nil && len(props) > 0 {
			evt.Props[props[0].Name] = props
		}
	}

	return evt.Component
}

func makeIcal(props ical.Props, components ...*ical.Component) *ical.Calendar {
	cal := ical.NewCalendar()

	if props != nil {
		maps.Copy(cal.Props, props)
	}

	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, "-//Proton AG//web-calendar 5.0.33.2//EN") // TODO: change?

	if components != nil {
		cal.Children = append(cal.Children, components...)
	}

	return cal
}

func getEventParts(event *ical.Event) (map[CalendarEventCardType]*ical.Calendar, map[CalendarEventCardType]*ical.Calendar) {
	sharedPart := make(map[CalendarEventCardType]*ical.Calendar)
	sharedPart[CalendarEventCardSigned] = makeIcal(nil, pickProps(event, sharedSignedFields))
	sharedPart[CalendarEventCardEncryptedAndSigned] = makeIcal(nil, pickProps(event, sharedEncryptedFields))

	calendarPart := make(map[CalendarEventCardType]*ical.Calendar)
	calendarPart[CalendarEventCardSigned] = makeIcal(nil, pickProps(event, calendarSignedFields))
	calendarPart[CalendarEventCardEncryptedAndSigned] = makeIcal(nil, pickProps(event, calendarEncryptedFields))

	// No personal part support for now
	/*personalPart := make(map[CalendarEventCardType]*ical.Calendar)
	personalPart[CalendarEventCardSigned] = pickProps(event, personalSignedFields)
	personalPart[CalendarEventCardEncryptedAndSigned] = pickProps(event, personalEncryptedFields)
	*/

	for _, propName := range usedFields {
		event.Props.Del(strings.ToUpper(propName))
	}
	for name, props := range event.Props {
		sharedPart[CalendarEventCardEncryptedAndSigned].Events()[0].Component.Props[strings.ToUpper(name)] = append(sharedPart[CalendarEventCardEncryptedAndSigned].Props[strings.ToUpper(name)], props...)
	}

	return sharedPart, calendarPart
}

func encodePart(part map[CalendarEventCardType]*ical.Calendar) (map[CalendarEventCardType]string, error) {
	encodedPart := make(map[CalendarEventCardType]string)
	for cardType, card := range part {
		icalData := new(bytes.Buffer)
		icalEncoder := ical.NewEncoder(icalData)
		err := icalEncoder.Encode(card)
		if err != nil {
			return nil, err
		}

		encodedPart[cardType] = icalData.String()
	}

	return encodedPart, nil
}

func decryptSessionKey(sessionKey string, calKr openpgp.KeyRing) (*packet.EncryptedKey, error) {
	if sessionKey == "" {
		return nil, nil
	}

	sharedKeyPacket := base64.NewDecoder(base64.StdEncoding, strings.NewReader(sessionKey))
	packetReader := packet.NewReader(sharedKeyPacket)

	pkt, err := packetReader.Next()
	if err != nil {
		return nil, err
	}

	switch pkt.(type) {
	case *packet.EncryptedKey:
		keyPacket := pkt.(*packet.EncryptedKey)
		decryptionKey := calKr.KeysById(keyPacket.KeyId)[0]
		if decryptionKey.PrivateKey.Encrypted {
			return nil, errors.New("decryption private key must be decrypted")
		}

		err := keyPacket.Decrypt(decryptionKey.PrivateKey, nil)
		if err != nil {
			return nil, err
		}
		return keyPacket, nil
	}

	return nil, errors.New("could not decrypt session key")
}

func getOrGenerateSessionKey(keyPacket string, calKr openpgp.KeyRing, config *packet.Config) (*packet.EncryptedKey, string, error) {
	var sessionKey *packet.EncryptedKey
	var encryptedSessionKey string
	if keyPacket != "" {
		encryptedSessionKey = keyPacket

		var err error
		sessionKey, err = decryptSessionKey(encryptedSessionKey, calKr)
		if err != nil {
			return nil, "", err
		}
	}

	if sessionKey == nil {
		var err error
		sessionKey, err = generateUnencryptedKey(packet.CipherAES256, config)
		if err != nil {
			return nil, "", err
		}

		calKeys := getCalKeys(calKr)
		calEncryptionKey, ok := encryptionKey(calKeys, config.Now())
		if !ok {
			return nil, "", errors.New("could not find encryption key for calKeys")
		}
		encryptedSessionKey, err = serializeEncryptedKey(sessionKey, calEncryptionKey.PublicKey, config)
	}

	return sessionKey, encryptedSessionKey, nil
}

func getCalKeys(calKr openpgp.KeyRing) *openpgp.Entity {
	return calKr.(openpgp.EntityList)[0] // Is the first key always the correct one?
}

func getUserKeys(userKr openpgp.KeyRing) *openpgp.Entity {
	return userKr.(openpgp.EntityList)[0] // Is the first key always the correct one?
}

func encryptPart(part string, key *packet.EncryptedKey, signer *openpgp.Entity, config *packet.Config) (string, error) {
	var signKey *packet.PrivateKey
	if signer != nil {
		signKeys, ok := signingKey(signer, config.Now())
		if !ok {
			return "", errors.New("no valid signing keys")
		}
		signKey = signKeys.PrivateKey
		if signKey == nil {
			return "", errors.New("no private key in signing key")
		}
		if signKey.Encrypted {
			return "", errors.New("signing key must be decrypted")
		}
	}

	encryptedBuf := new(bytes.Buffer)
	encryptedTextWriter := base64.NewEncoder(base64.StdEncoding, encryptedBuf)

	hints := openpgp.FileHints{
		IsBinary: true,
		ModTime:  config.Now(),
	}

	clearTextWriter, err := symetricallyEncrypt(encryptedTextWriter, key, signKey, &hints, config)
	if err != nil {
		return "", err
	}

	_, err = clearTextWriter.Write([]byte(part))
	if err != nil {
		return "", err
	}

	err = clearTextWriter.Close()
	if err != nil {
		return "", err
	}

	return encryptedBuf.String(), nil
}

func signPart(part string, signer *openpgp.Entity, config *packet.Config) (string, error) {
	signatureBuf := new(bytes.Buffer)
	if err := openpgp.ArmoredDetachSignText(signatureBuf, signer, strings.NewReader(part), config); err != nil {
		return "", err
	}

	return signatureBuf.String(), nil
}

func makeUpdateData(c *Client, calID string, oldEvent *CalendarEvent, event ical.Event, userKr openpgp.KeyRing) (*CalendarEventCreateOrUpdateData, string, error) {
	isCreate := oldEvent == nil

	bootstrap, err := c.BootstrapCalendar(calID)
	if err != nil {
		return nil, "", err
	}

	calKr, err := bootstrap.DecryptKeyring(userKr)
	if err != nil {
		return nil, "", err
	}

	sharedPartCal, calendarPartCal := getEventParts(&event)
	sharedPart, err := encodePart(sharedPartCal)
	if err != nil {
		return nil, "", err
	}
	calendarPart, err := encodePart(calendarPartCal)
	if err != nil {
		return nil, "", err
	}

	config := &packet.Config{}

	data := CalendarEventCreateOrUpdateData{}
	color := event.Props.Get("color")
	if color != nil && color.Value != "" {
		data.Color = &color.Value
	}
	data.Permissions = 1

	if oldEvent != nil {
		data.IsOrganizer = oldEvent.IsOrganizer
	} else {
		data.IsOrganizer = 1
	}

	// TODO CHECK WHICH KEYS TO USE FOR SIGNING
	userKeys := getUserKeys(userKr)
	if signedSharedPart, ok := sharedPart[CalendarEventCardSigned]; ok && signedSharedPart != "" {
		signature, err := signPart(signedSharedPart, userKeys, config)
		if err != nil {
			return nil, "", err
		}

		card := CalendarEventCard{
			Type:      CalendarEventCardSigned,
			Data:      signedSharedPart,
			Signature: signature,
		}

		data.SharedEventContent = append(data.SharedEventContent, card)
	}
	if encryptedSharedPart, ok := sharedPart[CalendarEventCardEncryptedAndSigned]; ok && encryptedSharedPart != "" {
		sharedKeyPacket := ""
		if oldEvent != nil {
			sharedKeyPacket = oldEvent.SharedKeyPacket
		}
		sharedSessionKey, encryptedSharedSessionKey, err := getOrGenerateSessionKey(sharedKeyPacket, calKr, config)
		if err != nil {
			return nil, "", err
		}

		if isCreate || sharedKeyPacket == "" {
			data.SharedKeyPacket = encryptedSharedSessionKey
		}

		signature, err := signPart(encryptedSharedPart, userKeys, config)
		if err != nil {
			return nil, "", err
		}

		encryptedData, err := encryptPart(encryptedSharedPart, sharedSessionKey, nil, config)
		if err != nil {
			return nil, "", err
		}

		card := CalendarEventCard{
			Type:      CalendarEventCardEncryptedAndSigned,
			Data:      encryptedData,
			Signature: signature,
		}

		md, err := card.Read(userKr, calKr, encryptedSharedSessionKey)
		if err != nil {
			return nil, "", err
		}

		_, err = io.ReadAll(md.UnverifiedBody)
		if err != nil {
			return nil, "", err // TODO: openpgp: "parsing error"
		}

		data.SharedEventContent = append(data.SharedEventContent, card)
	}

	// TODO check if actually needed
	if signedCalendarPart, ok := calendarPart[CalendarEventCardSigned]; ok && signedCalendarPart != "" {
		signature, err := signPart(signedCalendarPart, userKeys, config)
		if err != nil {
			return nil, "", err
		}

		card := CalendarEventCard{
			Type:      CalendarEventCardSigned,
			Data:      signedCalendarPart,
			Signature: signature,
		}

		data.CalendarEventContent = append(data.CalendarEventContent, card)
	}
	if encryptedCalendarPart, ok := calendarPart[CalendarEventCardEncryptedAndSigned]; ok && encryptedCalendarPart != "" {
		calendarKeyPacket := ""
		if oldEvent != nil {
			calendarKeyPacket = oldEvent.CalendarKeyPacket
		}
		calendarSessionKey, encryptedCalendarSessionKey, err := getOrGenerateSessionKey(calendarKeyPacket, calKr, config)
		if err != nil {
			return nil, "", err
		}

		if isCreate || calendarKeyPacket == "" {
			data.CalendarKeyPacket = encryptedCalendarSessionKey
		}

		signature, err := signPart(encryptedCalendarPart, userKeys, config)
		if err != nil {
			return nil, "", err
		}

		encryptedData, err := encryptPart(encryptedCalendarPart, calendarSessionKey, nil, config)
		if err != nil {
			return nil, "", err
		}

		card := CalendarEventCard{
			Type:      CalendarEventCardEncryptedAndSigned,
			Data:      encryptedData,
			Signature: signature,
		}

		md, err := card.Read(userKr, calKr, encryptedCalendarSessionKey)
		if err != nil {
			return nil, "", err
		}

		_, err = io.ReadAll(md.UnverifiedBody)
		if err != nil {
			return nil, "", err
		}

		data.CalendarEventContent = append(data.CalendarEventContent, card)
	}

	// Attendees encrypted and clear parts ...
	// Removed attendees emails ...
	// Attendees encrypted session keys ...
	// Cancelled occurrence parts ...

	member, err := FindMemberViewFromKeyring(bootstrap.Members, userKr)
	if err != nil {
		return nil, "", err
	}

	return &data, member.ID, nil
}

func (c *Client) UpdateCalendarEvent(calID string, eventID string, event ical.Event, userKr openpgp.KeyRing) (*CalendarEvent, error) {
	oldEvent, err := c.GetCalendarEvent(calID, eventID)
	isCreate := false
	if apiErr, ok := err.(*APIError); ok && apiErr.Code == 2061 {
		isCreate = true
	} else if err != nil {
		return nil, err
	}

	data, memberID, err := makeUpdateData(c, calID, oldEvent, event, userKr)
	if err != nil {
		return nil, err
	}

	var entry interface{}
	if isCreate {
		entry = CalendarEventCreateSyncEntry{
			Event: data,
		}
	} else {
		entry = CalendarEventUpdateSyncEntry{
			ID:    eventID,
			Event: data,
		}
	}

	body := CalendarEventSyncReq{
		MemberID: memberID,
		Events: []interface{}{
			entry,
		},
	}

	req, err := c.newJSONRequest(http.MethodPut, calendarPath+"/"+calID+"/events/sync", body)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Responses []struct {
			Event CalendarEvent
		}
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, err
	}
	str := buf.String()
	_ = str

	req.Header.Set("Accept", "application/json")

	respd, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer respd.Body.Close()

	respbytes, _ := io.ReadAll(respd.Body)
	resps := string(respbytes)
	_ = resps
	if err := json.NewDecoder(bytes.NewReader(respbytes)).Decode(&respData); err != nil {
		return nil, err
	}

	if c.Debug {
		log.Printf("<< %v %v", req.Method, req.URL.Path)
		log.Printf("%#v", respData)
	}

	if len(respData.Responses) != 1 {
		return nil, errors.New("no response on events sync")
	}

	return &respData.Responses[0].Event, nil

	/*if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return nil, nil
		if len(respData.Responses) != 1 {
			return nil, errors.New("no response on events sync")
		}

		return &respData.Responses[0].Event, nil*/
}

type CalendarEventDeleteSyncEntry struct {
	ID             string
	DeletionReason int
}

func (c *Client) DeleteCalendarEvent(calID string, eventID string) error {
	body := CalendarEventSyncReq{
		Events: []interface{}{
			CalendarEventDeleteSyncEntry{
				ID:             eventID,
				DeletionReason: 0,
			},
		},
	}

	req, err := c.newJSONRequest(http.MethodPut, calendarPath+"/"+calID+"/events/sync", body)
	if err != nil {
		return err
	}

	if _, err := c.do(req); err != nil {
		return err
	}

	return nil
}
