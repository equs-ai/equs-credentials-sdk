import {
  ProofOfPossessionMetadata,
  InnerProofOfPossessionNotBefore,
  InnerProofOfPossessionNotBeforeStrategy,
} from "../../../binary";

export class ProofOfPossessionMetadataBuilder {
  private lifetime?: number;
  private notBefore?: InnerProofOfPossessionNotBefore;

  withLifetime(lifetime_secs: number): this {
    this.lifetime = lifetime_secs;
    return this;
  }

  withNotBefore(notBefore: InnerProofOfPossessionNotBefore): this {
    this.notBefore = notBefore;
    return this;
  }

  build(): ProofOfPossessionMetadata {
    return {
      lifetime: this.lifetime,
      notBefore: this.notBefore,
    };
  }
}

export class ProofOfPossessionNotBefore {
  static asIssuedAt(): InnerProofOfPossessionNotBefore {
    return {
      strategy: InnerProofOfPossessionNotBeforeStrategy.AsIssuedAt,
    };
  }

  static fixed(date: Date): InnerProofOfPossessionNotBefore {
    return {
      strategy: InnerProofOfPossessionNotBeforeStrategy.Fixed,
      fixed: date,
    };
  }

  static delay(delay_secs: number): InnerProofOfPossessionNotBefore {
    return {
      strategy: InnerProofOfPossessionNotBeforeStrategy.Delay,
      delay: delay_secs,
    };
  }

  static leeway(leeway_secs: number): InnerProofOfPossessionNotBefore {
    return {
      strategy: InnerProofOfPossessionNotBeforeStrategy.Leeway,
      leeway: leeway_secs,
    };
  }
}
