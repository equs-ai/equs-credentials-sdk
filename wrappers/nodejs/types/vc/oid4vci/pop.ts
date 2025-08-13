import {
  Duration,
  ProofOfPossessionMetadata,
  ProofOfPossessionNotBefore,
  ProofOfPossessionNotBeforeStrategy,
} from "../../../binary";

export class ProofOfPossessionMetadataBuilder {
  private lifetime?: Duration;
  private notBefore?: ProofOfPossessionNotBefore;

  withLifetime(lifetime: Duration): this {
    this.lifetime = lifetime;
    return this;
  }

  withNotBefore(notBefore: ProofOfPossessionNotBefore): this {
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

export class ProofOfPossessionNotBeforeFactory {
  static asIssuedAt(): ProofOfPossessionNotBefore {
    return {
      strategy: ProofOfPossessionNotBeforeStrategy.AsIssuedAt,
    };
  }

  static fixed(date: Date): ProofOfPossessionNotBefore {
    return {
      strategy: ProofOfPossessionNotBeforeStrategy.Fixed,
      fixed: date,
    };
  }

  static delay(delay: Duration): ProofOfPossessionNotBefore {
    return {
      strategy: ProofOfPossessionNotBeforeStrategy.Delay,
      delay: delay,
    };
  }

  static leeway(leeway: Duration): ProofOfPossessionNotBefore {
    return {
      strategy: ProofOfPossessionNotBeforeStrategy.Leeway,
      leeway: leeway,
    };
  }
}
