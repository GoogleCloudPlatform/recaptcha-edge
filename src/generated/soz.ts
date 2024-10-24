/**
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// @generated by protobuf-ts 2.9.4
// @generated from protobuf file "soz.proto" (package "recaptcha.soz", syntax proto3)
// tslint:disable
import type {
  BinaryReadOptions,
  BinaryWriteOptions,
  IBinaryReader,
  IBinaryWriter,
  PartialMessage,
} from '@protobuf-ts/runtime';
import {
  MessageType,
  reflectionMergePartial,
  UnknownFieldHandler,
  WireType,
} from '@protobuf-ts/runtime';
import {Duration} from './google/protobuf/duration';
import {Timestamp} from './google/protobuf/timestamp';
/**
 * When a request for a cloud service is blocked by a redirect-to-recaptcha
 * action, the WAF fills in this protobuf and passes it in the
 * X-Google-ReCaptcha-Soz header to instruct Recaptcha to forward directly to
 * the reCAPTCHA service via an internal redirect. Note that the
 * X-Google-ReCaptcha-Soz header is only used internally, and should never be
 * included in the response back to the user. Note that this protobuf can be
 * expanded to carry customization information for future uses.
 *
 * @generated from protobuf message recaptcha.soz.ReCaptchaSoz
 */
export interface ReCaptchaSoz {
  /**
   * Original user IP from the blocked request. Recording here to avoid proxies
   * sending requests to the reCAPTCHA service from a different IP.
   *
   * @generated from protobuf field: optional bytes user_ip = 1;
   */
  userIp?: Uint8Array;
  /**
   * Original Host header of the blocked request.
   *
   * @generated from protobuf field: optional string host = 5;
   */
  host?: string;
  /**
   * Original URI of the blocked request. Note that the URI is NOT guaranteed
   * to have a host, as it can be relative, i.e., only contain the relative path
   * without the protocol or host information.
   *
   * @generated from protobuf field: optional string uri = 6;
   */
  uri?: string;
  /**
   * Timestamp (in epoch seconds) when the request is initially blocked (for
   * tracking purpose).
   *
   * @generated from protobuf field: optional google.protobuf.Timestamp timestamp = 2;
   */
  timestamp?: Timestamp;
  /**
   * Public site key obtained when registering with the reCAPTCHA console. This
   * will be used by reCAPTCHA to prepare the redirect page. The reCAPTCHA type
   * is v2 invisible for now.
   *
   * @generated from protobuf field: optional string site_key = 3;
   */
  siteKey?: string;
  /**
   * Allowed duration of the exemption cookie. The actual duration can be
   * smaller when the exemption cookie is issued by reCAPTCHA.
   *
   * @generated from protobuf field: optional google.protobuf.Duration exempt_duration = 4;
   */
  exemptDuration?: Duration;
  /**
   * Project number where the security policy is configured. For reCAPTCHA
   * analysis purposes.
   *
   * @generated from protobuf field: optional uint64 project_number = 7;
   */
  projectNumber?: bigint;
}
// @generated message type with reflection information, may provide speed optimized methods
class ReCaptchaSoz$Type extends MessageType<ReCaptchaSoz> {
  constructor() {
    super('recaptcha.soz.ReCaptchaSoz', [
      {
        no: 1,
        name: 'user_ip',
        kind: 'scalar',
        opt: true,
        T: 12 /*ScalarType.BYTES*/,
      },
      {
        no: 5,
        name: 'host',
        kind: 'scalar',
        opt: true,
        T: 9 /*ScalarType.STRING*/,
      },
      {
        no: 6,
        name: 'uri',
        kind: 'scalar',
        opt: true,
        T: 9 /*ScalarType.STRING*/,
      },
      {no: 2, name: 'timestamp', kind: 'message', T: () => Timestamp},
      {
        no: 3,
        name: 'site_key',
        kind: 'scalar',
        opt: true,
        T: 9 /*ScalarType.STRING*/,
      },
      {no: 4, name: 'exempt_duration', kind: 'message', T: () => Duration},
      {
        no: 7,
        name: 'project_number',
        kind: 'scalar',
        opt: true,
        T: 4 /*ScalarType.UINT64*/,
        L: 0 /*LongType.BIGINT*/,
      },
    ]);
  }
  create(value?: PartialMessage<ReCaptchaSoz>): ReCaptchaSoz {
    const message = globalThis.Object.create(this.messagePrototype!);
    if (value !== undefined)
      reflectionMergePartial<ReCaptchaSoz>(this, message, value);
    return message;
  }
  internalBinaryRead(
    reader: IBinaryReader,
    length: number,
    options: BinaryReadOptions,
    target?: ReCaptchaSoz,
  ): ReCaptchaSoz {
    let message = target ?? this.create(),
      end = reader.pos + length;
    while (reader.pos < end) {
      let [fieldNo, wireType] = reader.tag();
      switch (fieldNo) {
        case /* optional bytes user_ip */ 1:
          message.userIp = reader.bytes();
          break;
        case /* optional string host */ 5:
          message.host = reader.string();
          break;
        case /* optional string uri */ 6:
          message.uri = reader.string();
          break;
        case /* optional google.protobuf.Timestamp timestamp */ 2:
          message.timestamp = Timestamp.internalBinaryRead(
            reader,
            reader.uint32(),
            options,
            message.timestamp,
          );
          break;
        case /* optional string site_key */ 3:
          message.siteKey = reader.string();
          break;
        case /* optional google.protobuf.Duration exempt_duration */ 4:
          message.exemptDuration = Duration.internalBinaryRead(
            reader,
            reader.uint32(),
            options,
            message.exemptDuration,
          );
          break;
        case /* optional uint64 project_number */ 7:
          message.projectNumber = reader.uint64().toBigInt();
          break;
        default:
          let u = options.readUnknownField;
          if (u === 'throw')
            throw new globalThis.Error(
              `Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`,
            );
          let d = reader.skip(wireType);
          if (u !== false)
            (u === true ? UnknownFieldHandler.onRead : u)(
              this.typeName,
              message,
              fieldNo,
              wireType,
              d,
            );
      }
    }
    return message;
  }
  internalBinaryWrite(
    message: ReCaptchaSoz,
    writer: IBinaryWriter,
    options: BinaryWriteOptions,
  ): IBinaryWriter {
    /* optional bytes user_ip = 1; */
    if (message.userIp !== undefined)
      writer.tag(1, WireType.LengthDelimited).bytes(message.userIp);
    /* optional string host = 5; */
    if (message.host !== undefined)
      writer.tag(5, WireType.LengthDelimited).string(message.host);
    /* optional string uri = 6; */
    if (message.uri !== undefined)
      writer.tag(6, WireType.LengthDelimited).string(message.uri);
    /* optional google.protobuf.Timestamp timestamp = 2; */
    if (message.timestamp)
      Timestamp.internalBinaryWrite(
        message.timestamp,
        writer.tag(2, WireType.LengthDelimited).fork(),
        options,
      ).join();
    /* optional string site_key = 3; */
    if (message.siteKey !== undefined)
      writer.tag(3, WireType.LengthDelimited).string(message.siteKey);
    /* optional google.protobuf.Duration exempt_duration = 4; */
    if (message.exemptDuration)
      Duration.internalBinaryWrite(
        message.exemptDuration,
        writer.tag(4, WireType.LengthDelimited).fork(),
        options,
      ).join();
    /* optional uint64 project_number = 7; */
    if (message.projectNumber !== undefined)
      writer.tag(7, WireType.Varint).uint64(message.projectNumber);
    let u = options.writeUnknownFields;
    if (u !== false)
      (u == true ? UnknownFieldHandler.onWrite : u)(
        this.typeName,
        message,
        writer,
      );
    return writer;
  }
}
/**
 * @generated MessageType for protobuf message recaptcha.soz.ReCaptchaSoz
 */
export const ReCaptchaSoz = new ReCaptchaSoz$Type();
